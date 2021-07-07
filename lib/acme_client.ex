defmodule AcmeClient do
  @moduledoc """
  Documentation for `AcmeClient`.
  """
  require Logger
  alias AcmeClient.Session
  @app :acme_client

  @type code :: non_neg_integer()
  @type client :: Tesla.Env.client()
  @type reason :: any()
  @type nonce :: binary()
  @type request_ret :: {:ok, Session.t(), term()} | {:error, Session.t(), term()} | {:error, term()}

  @type headers :: list({binary(), binary()})

  @doc """
  Hello world.

  ## Examples

      iex> AcmeClient.hello()
      :world

  """
  def hello do
    :world
  end


  @doc ~S"""
  Create new session connecting to ACME server."

  Sets up the Tesla client library, then reads the server's directory URL,
  which maps standard names for operations to the specific URLs on the server.

  Params:

  * directory_url: Server directory URL.
                   Defaults to staging server `https://acme-staging-v02.api.letsencrypt.org/directory`.
                   Production is `https://acme-v02.api.letsencrypt.org/directory`
  * middleware: Tesla middlewares (optional)
  * adapter: Tesla adapter (optional)
  * account_key: ACME account key (optional)
  * account_kid: ACME account key id, a URL (optional)

  ## Examples

    {:ok, account_key} = AcmeClient.generate_account_key()
    contact = "mailto:admin@example.com"
    {:ok, session, account} = AcmeClient.new_secreate_account(account_key: account_key, contact: contact)

    {:ok, session} = AcmeClient.new_session(account_key: account_key, account_kid: account_kid)
    {:ok, session} = AcmeClient.new_nonce(session)
  """
  @spec new_session(Keyword.t()) :: {:ok, Session.t()} | {:error, term()}
  def new_session(opts \\ []) do
    directory_url = opts[:directory_url] || "https://acme-staging-v02.api.letsencrypt.org/directory"
    opts_middleware = opts[:middleware] || []
    adapter = opts[:adapter]
    session = %Session{
      account_key: opts[:account_key],
      account_kid: opts[:account_kid],
    }

    middleware = opts_middleware ++ [
      {Tesla.Middleware.JSON, decode_content_types: [
        "application/problem+json",
      ]},
      Tesla.Middleware.Logger,
    ]

    client = Tesla.client(middleware, adapter)
    case Tesla.request(client, method: :get, url: directory_url) do
      {:ok, %{status: 200, body: body}} ->
        {:ok, %{session | client: client, directory: body}}
      {:ok, result} ->
        {:error, result}
      {:error, reason} ->
        {:error, reason}
    end
  end

  @doc "Get nonce from server and add to session"
  @spec new_nonce(Session.t()) :: {:ok, Session.t()} | {:error, term()}
  def new_nonce(session) do
    url = session.directory["newNonce"]
    case Tesla.request(session.client, method: :head, url: url) do
      {:ok, %{status: 200, headers: headers}} ->
        {:ok, set_nonce(session, headers)}
      {:ok, result} ->
        {:error, result}
      {:error, reason} ->
        {:error, reason}
    end
  end

  @doc ~S"""
  Convenience function which creates a session.

  Params:
    * directory_url (optional)
    * account_key: Account key (optional)
    * account_kid: Account key id URL (optional)

  If params are not specified, they are read from the environment.

  ## Examples

    {:ok, session} = AcmeClient.create_session()
  """
  @spec create_session(Keyword.t()) :: {:ok, Session.t()} | {:error, term()}
  def create_session(params \\ []) do
    url =
      case Keyword.fetch(params, :directory_url) do
        {:ok, value} ->
          value
        :error ->
          Application.get_env(@app, :directory_url)
      end

    key =
      case Keyword.fetch(params, :account_key) do
        {:ok, value} ->
          value
        :error ->
          account_key_bin = Application.get_env(@app, :account_key)
          AcmeClient.binary_to_key(account_key_bin)
      end

    kid =
      case Keyword.fetch(params, :account_kid) do
        {:ok, value} ->
          value
        :error ->
          Application.get_env(@app, :account_kid)
      end

    {:ok, session} = new_session(directory_url: url, account_key: key, account_kid: kid)
    new_nonce(session)
  end


  @doc ~S"""
  Perform POST-as-GET HTTP call.

  This reads a URL from the server. Instead of using GET, it uses POST so that the
  request has the proper signing and nonce.
  #
  ## Examples
    {:ok, session, response} = AcmeClient.post_as_get(session, "https://acme-staging-v02.api.letsencrypt.org/acme/acct/123")
  """
  @spec post_as_get(Session.t(), binary()) :: {:ok, Session.t(), term()} | {:error, term()}
  def post_as_get(session, url, payload \\ "") do
    %{client: client, account_key: account_key, account_kid: kid, nonce: nonce} = session
    req_headers = [{"content-type", "application/jose+json"}]

    protected = %{"alg" => "ES256", "kid" => kid, "nonce" => nonce, "url" => url}
    {_, body} = JOSE.JWS.sign(account_key, payload, protected)

    case Tesla.request(client, method: :post, url: url, body: body, headers: req_headers) do
      {:ok, %{status: 200, headers: headers} = result} ->
        session = set_nonce(session, headers)
        {:ok, session, result}
      {:ok, %{headers: headers} = result} ->
        {:error, set_nonce(session, headers), result}
      {:error, reason} ->
        {:error, reason}
    end
  end

  @doc "Get a list of URLs with post_as_get"
  @spec get_urls(Session.t(), list(binary())) :: {:ok, Session.t(), term()}
  def get_urls(session, urls) do
    {session, results} =
      Enum.reduce(urls, {session, []},
        fn url, {session, acc} ->
          {:ok, session, result} = AcmeClient.post_as_get(session, url)
          {session, [{url, result.body} | acc]}
        end)
    {:ok, session, Enum.reverse(results)}
  end

  @doc ~S"""
  Generate JWS cryptographic key for account.
  """
  @spec generate_account_key(Keyword.t()) :: {:ok, JOSE.JWK.t()}
  def generate_account_key(opts \\ []) do
    alg = opts[:alg] || "ES256"
    {:ok, JOSE.JWS.generate_key(%{"alg" => alg})}
  end

  # def generate_account_key(opts) do
  #   key_size = opts[:key_size] || 2048
  #   JOSE.JWK.generate_key({:rsa, key_size})
  # end


  @doc ~S"""
  Create new ACME account.

  Params:
    * account_key: Account key, from `generate_account_key/1`
    * contact: Account owner contact(s), e.g. "mailto:jake@cogini.com", string
               or array of strings.
    * terms_of_service_agreed: true (optional)
    * only_return_existing: true (optional)
    * external_account_binding: associated external account (optional)

  ## Examples

    {:ok, account_key} = AcmeClient.generate_account_key()
    params = [
      account_key: account_key,
      contact: "mailto:admin@example.com",
      terms_of_service_agreed: true,
    ]
    {:ok, session} = new_session()
    {:ok, session} = new_nonce(session)
    {:ok, session, account} = AcmeClient.create_account(params)
  """
  @spec new_account(Session.t(), Keyword.t()) :: {:ok, Session.t(), map()} | {:error, Session.t(), Tesla.Env.result()} | {:error, term()}
  def new_account(session, opts) do
    %{client: client, directory: directory, account_key: account_key, nonce: nonce} = session
    url = directory["newAccount"]
    req_headers = [{"content-type", "application/jose+json"}]

    map_opts =
      fn
        {:contact, value} = pair when is_list(value) -> pair
        {:contact, value} when is_binary(value) -> {:contact, [value]}
        {:terms_of_service_agreed, true} -> {"termsOfServiceAgreed", true}
        {:only_return_existing, true} -> {"onlyReturnExisting", true}
        {:external_account_binding, value} -> {"externalAccountBinding", value}
    end

    payload =
      opts
      |> Keyword.take([:contact, :terms_of_service_agreed, :only_return_existing, :external_account_binding])
      |> Enum.map(map_opts)
      |> Enum.into(%{})
      |> Jason.encode!()

    protected = %{"alg" => "ES256", "nonce" => nonce, "url" => url, jwk: to_jwk(account_key)}
    {_, body} = JOSE.JWS.sign(account_key, payload, protected)

    case Tesla.request(client, method: :post, url: url, body: body, headers: req_headers) do
      # returns 201 on initial create, 200 if called again
      {:ok, %{status: status, headers: headers} = result} when status in [201, 200] ->
        session = set_nonce(session, headers)
        value = %{
          object: result.body,
          location: :proplists.get_value("location", headers, nil)
        }
        {:ok, session, value}
      {:ok, %{headers: headers} = result} ->
        {:error, set_nonce(session, headers), result}
      {:error, reason} ->
        {:error, reason}
    end
  end

  @doc ~S"""
  Create HTTP challenge URL for token.

  https://datatracker.ietf.org/doc/html/rfc8555#section-8.3

  Response:

    HTTP/1.1 200 OK
    Content-Type: application/octet-stream

    <key_authorization>
  """
  @spec http_challenge_url(binary()) :: binary()
  def http_challenge_url(token) do
    "/.well-known/acme-challenge/" <> token
  end


  @doc ~S"""
  Create key authorization from token and key.

  https://datatracker.ietf.org/doc/html/rfc8555#section-8.1
  """
  @spec key_authorization(binary(), JOSE.JWK.t()) :: binary()
  def key_authorization(token, key) do
    token <> "." <> key_thumbprint(key)
  end


  @doc ~S"""
  Generate RFC7638 thumbprint of key.

  https://datatracker.ietf.org/doc/html/rfc7638

  ## Examples

    AcmeClient.key_thumbprint(account_key)
  """
  @spec key_thumbprint(JOSE.JWK.t()) :: binary()
  def key_thumbprint(key) do
    key
    |> JOSE.JWK.to_thumbprint_map()
    |> JOSE.JWK.thumbprint()
  end


  @doc ~S"""
  Generate DNS challenge response.

  https://datatracker.ietf.org/doc/html/rfc8555#section-8.4

    _acme-challenge.www.example.org. 300 IN TXT "<key_authorization>"

  """
  def dns_challenge_response(token, key) do
    token
    |> key_authorization(key)
    |> (&(:crypto.hash(:sha256, &1))).()
    |> Base.url_encode64(padding: false, case: :lower)
  end


  @doc ~S"""
  Create new order.

  Params:

  * identifiers: domain(s), either binary value or type/value map
  * not_before: datetime in RFC3339 (ISO8601) format (optional)
  * not_after: datetime in RFC3339 (ISO8601) format (optional)

  `account_key` and `account_kid` must be set in session.
  """
  @spec new_order(Session.t(), Keyword.t()) :: {:ok, Session.t(), map()} | {:error, Session.t(), Tesla.Env.result()}
  def new_order(session, opts) do
    %{client: client, directory: directory, account_key: account_key, account_kid: kid, nonce: nonce} = session
    url = directory["newOrder"]
    req_headers = [{"content-type", "application/jose+json"}]

    map_identifier =
      fn
        value when is_binary(value) -> %{type: "dns", value: value}
        value when is_map(value) -> value
      end

    map_opts =
      fn
        {:identifiers, value} when is_binary(value) ->
          {:identifiers, [%{type: "dns", value: value}]}
        {:identifiers, value} when is_map(value) ->
          {:identifiers, [value]}
        {:identifiers, values} when is_list(values) ->
          {:identifiers, Enum.map(values, map_identifier)}
        {:not_before, value} when is_binary(value) ->
          {"notBefore", value}
        {:not_after, value} when is_binary(value) ->
          {"notAfter", value}
    end

    payload =
      opts
      |> Keyword.take([:identifiers, :not_before, :not_after])
      |> Enum.map(map_opts)
      |> Enum.into(%{})
      |> Jason.encode!()

    protected = %{"alg" => "ES256", "kid" => kid, "nonce" => nonce, "url" => url}
    {_, body} = JOSE.JWS.sign(account_key, payload, protected)

    case Tesla.request(client, method: :post, url: url, body: body, headers: req_headers) do
      {:ok, %{status: status, headers: headers} = result} when status in [200] ->
        session = set_nonce(session, headers)
        value = %{
          object: result.body,
          location: :proplists.get_value("location", headers, nil)
        }
        {:ok, session, value}
      {:ok, %{headers: headers} = result} ->
        {:error, set_nonce(session, headers), result}
      {:error, reason} ->
        {:error, reason}
    end
  end

  @doc ~S"""
  Create challenge responses for order.

  ## Examples
    AcmeClient.create_challenge_responses(session, "https://acme-staging-v02.api.letsencrypt.org/acme/order/123/456")
  """
  # %{
  #     "authorizations" => ["https://acme-staging-v02.api.letsencrypt.org/acme/authz-v3/82803238",
  #      "https://acme-staging-v02.api.letsencrypt.org/acme/authz-v3/82803239"],
  #     "expires" => "2021-07-12T20:22:34Z",
  #     "finalize" => "https://acme-staging-v02.api.letsencrypt.org/acme/finalize/20177848/94029681",
  #     "identifiers" => [
  #       %{"type" => "dns", "value" => "cogini.com"},
  #       %{"type" => "dns", "value" => "www.cogini.com"}
  #     ],
  #     "status" => "pending"
  # },
  @spec create_challenge_responses(Session.t(), binary()) :: {:ok, Session.t(), list({binary(), map()})} | {:error, term()}
  def create_challenge_responses(session, order_url) do
    key = session.account_key
    with {:ok, session, order} <- AcmeClient.post_as_get(session, order_url),
         {:ok, session, authorizations} <- AcmeClient.get_urls(session, order.body["authorizations"])
    do
      responses =
        for {url, authorization} <- authorizations do
          {url, authorization_response(authorization, key)}
        end
      {:ok, session, responses}
    else
      err -> err
    end
  end

  def authorization_response(authorization, key) do
    challenges =
      for challenge <- authorization["challenges"] do
        challenge_add_response(challenge, key)
      end
    Map.put(authorization, "challenges", challenges)
  end

  def challenge_add_response(%{"type" => "dns-01", "token" => token} = challenge, key) do
    Map.put(challenge, "response", dns_challenge_response(token, key))
  end

  def challenge_add_response(%{"type" => "http-01", "token" => token} = challenge, key) do
    Map.put(challenge, "response", key_authorization(token, key))
  end

  def challenge_add_response(challenge, _key), do: challenge

  # def create_order(session, opts) do
  #   {:ok, session, order} = AcmeClient.new_order(session, opts)
  #   {:ok, session, challenges} = AcmeClient.get_order_challenges(session, order)
  # end

  @doc ~S"""
  Create Tesla client.

  Options are:

  * base_url: URL of server (optional), default "https://acme-staging-v02.api.letsencrypt.org/directory"
  * adapter: HTTP client adapter (optional)
  * middleware: Additional Tesla middleware modules (optional)

  ## Examples

      iex> client = AcmeClient.create_client()
      %Tesla.Client{
        adapter: nil,
        fun: nil,
        post: [],
        pre: [
          {Tesla.Middleware.BaseUrl, :call,
           ["https://acme-staging-v02.api.letsencrypt.org/directory"]},
          {Tesla.Middleware.JSON, :call, [[]]}
        ]
      }
  """
  @spec create_client(Keyword.t()) :: Tesla.Client.t()
  def create_client(opts \\ []) do
    base_url = opts[:base_url] || "https://acme-staging-v02.api.letsencrypt.org/directory"
    adapter = opts[:adapter]

    opts_middleware = opts[:middleware] || []
    middleware = opts_middleware ++ [
      {Tesla.Middleware.BaseUrl, base_url},
      Tesla.Middleware.JSON,
    ]

    Tesla.client(middleware, adapter)
  end

  @spec get_directory(Tesla.Client.t()) :: {:ok, map()} | {:error, map()}
  def get_directory(client) do
    do_get(client, "/directory")
  end


  # Internal utility functions

  # Set session nonce from server response headers
  @spec set_nonce(Session.t(), headers()) :: Session.t()
  defp set_nonce(session, headers) do
    %{session | nonce: extract_nonce(headers)}
  end

  @doc "Get nonce from headers"
  @spec extract_nonce(headers()) :: binary() | nil
  def extract_nonce(headers) do
    :proplists.get_value("replay-nonce", headers, nil)
  end

  @spec update_nonce(Session.t(), headers()) :: Session.t()
  def update_nonce(session, headers) do
    %{session | nonce: :proplists.get_value("replay-nonce", headers)}
  end

  # Convert key to JWK representation used in API
  defp to_jwk(account_key) do
    {_modules, public_map} = JOSE.JWK.to_public_map(account_key)
    public_map
  end

  # Convert key struct to binary
  def key_to_binary(key) do
    {_type, value} = JOSE.JWK.to_binary(key)
    value
  end

  # Convert binary to key struct
  def binary_to_key(bin) do
    JOSE.JWK.from_binary(bin)
  end


  @spec do_get(Tesla.Client.t(), binary()) :: {:ok, map()} | {:error, map()}
  def do_get(client, url) do
    tesla_response(Tesla.get(client, url))
  end

  defp tesla_response({:ok, %{status: 200, body: body}}), do: {:ok, body}
  defp tesla_response({:ok, %{status: status, body: body}}), do: {:error, %{status: status, body: body}}
  defp tesla_response({:error, reason}), do: {:error, %{status: 0, reason: reason}}

  @spec request(client(), Session.t(), Keyword.t()) :: request_ret()
  def request(client, session, options \\ []) do
    default_options = [
      method: :post,
      status: 200,
    ]
    options = Keyword.merge(default_options, options)
    {status, options} = Keyword.pop(options, :status)

    Logger.debug("client: #{inspect(client)}")
    Logger.debug("session: #{inspect(session)}")
    Logger.debug("options: #{inspect(options)}")
    Logger.debug("status: #{inspect(status)}")

    case Tesla.request(client, options) do
      {:ok, %{status: ^status, headers: headers} = result} ->
        {:ok, set_nonce(session, headers), result}
      {:ok, %{headers: headers} = result} ->
        {:error, set_nonce(session, headers), result}
      {:error, reason} ->
        {:error, reason}
    end
  end
end
