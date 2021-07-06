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

  This sets up Tesla to talk to the server, then reads the directory URL.

  Params:

  * directory_url: Server directory URL, which gives references to other endpoints.
                   Defaults to `https://acme-staging-v02.api.letsencrypt.org/directory`.
                   For production, `https://acme-v02.api.letsencrypt.org/directory`
  * middleware: Tesla middlewares (optional)
  * adapter: Tesla adapter (optional)
  * account_key: ACME account key (optional)

  ## Examples

    contact = "mailto:admin@example.com"
    {:ok, account_key} = AcmeClient.generate_account_key()
    {:ok, session, account} = AcmeClient.create_account(account_key: account_key, contact: contact)
  """
  @spec new_session(Keyword.t()) :: {:ok, Session.t()} | {:error, term()}
  def new_session(opts \\ []) do
    directory_url = opts[:directory_url] || "https://acme-staging-v02.api.letsencrypt.org/directory"
    opts_middleware = opts[:middleware] || []
    adapter = opts[:adapter]
    session = %Session{
      account_key: opts[:account_key],
      account_kid: opts[:account_kid]
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

  # body: "{\n  \"type\": \"urn:ietf:params:acme:error:malformed\",\n  \"detail\": \"Request payload did not parse as JSON\",\n  \"status\": 400\n}",

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

  @doc "Generate cryptographic key for account"
  @spec generate_account_key(Keyword.t()) :: {:ok, JOSE.JWK.t()}
  def generate_account_key(params \\ []) do
    alg = params[:alg] || "ES256"
    {:ok, JOSE.JWS.generate_key(%{"alg" => alg})}
  end
  # def generate_account_key(params) do
  #   key_size = params[:key_size] || 2048
  #   JOSE.JWK.generate_key({:rsa, key_size})
  # end

  # HTTP challenge
  # url = "/.well-known/acme-challenge/" <> token
  #
  # Response
  # HTTP/1.1 200 OK
  # Content-Type: application/octet-stream
  #
  # <key_authorization>

  # DNS challenge
  # _acme-challenge.www.example.org. 300 IN TXT "<key_authorization>"

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

  ## Examples

    AcmeClient.key_thumbprint(session.account_key)
  """
  @spec key_thumbprint(JOSE.JWK.t()) :: binary()
  def key_thumbprint(key) do
    key
    |> JOSE.JWK.to_thumbprint_map()
    |> JOSE.JWK.thumbprint()
  end

  @doc ~S"""
  Generate DNS validation value.

  https://datatracker.ietf.org/doc/html/rfc8555#section-8.4

  """
  def dns_validation(token, key) do
    token
    |> key_authorization(key)
    |> (&(:crypto.hash(:sha256, &1))).()
    |> Base.url_encode64(case: :lower)
    # |> Base.url_encode64(padding: false, case: :lower)
  end

  # %{
  #   "contact" => ["mailto:jake@cogini.com"],
  #   "createdAt" => "2021-01-21T02:25:34.191981376Z",
  #   "initialIp" => "123.194.199.220",
  #   "key" => %{
  #     "alg" => "ES256",
  #     "crv" => "P-256",
  #     "kty" => "EC",
  #     "use" => "sig",
  #     "x" => "kk1Lezgf2nsLAc2_Is8pP2KGJRTvTBF2EfPpJgRxWuo",
  #     "y" => "iDsb47bohf2_HMTfo5BGwp4PrjGce7jicc7Jix4B5Yg"
  #   },
  #   "status" => "valid"
  # }}
  #
  # %{
  #   "detail" => "must agree to terms of service",
  #   "status" => 400,
  #   "type" => "urn:ietf:params:acme:error:malformed"
  # }

  @doc ~S"""
  Create new account.

  Params:

  * account_key: Account key, from `generate_account_key/1`
  * contact: Account owner contact(s), e.g. "mailto:jake@cogini.com" (optional)
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
  @spec new_account(Session.t(), Keyword.t()) :: {:ok, Session.t(), map()} | {:error, Session.t(), Tesla.Env.result()}
  def new_account(session, opts) do
    %{client: client, directory: directory, account_key: account_key, nonce: nonce} = session
    url = directory["newAccount"]
    req_headers = [{"content-type", "application/jose+json"}]

    payload =
      opts
      |> Enum.reduce(%{}, &reduce_new_account_opts/2)
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

  # Convert new_account/2 params to name/format required by API
  defp reduce_new_account_opts({:contact, value}, acc) when is_list(value) do
    Map.put(acc, "contact", value)
  end

  defp reduce_new_account_opts({:contact, value}, acc) when is_binary(value) do
    Map.put(acc, "contact", [value])
  end

  defp reduce_new_account_opts({:terms_of_service_agreed, true}, acc) do
    Map.put(acc, "termsOfServiceAgreed", true)
  end

  defp reduce_new_account_opts({:only_return_existing, true}, acc) do
    Map.put(acc, "onlyReturnExisting", true)
  end

  defp reduce_new_account_opts({:external_account_binding, value}, acc) do
    Map.put(acc, "externalAccountBinding", value)
  end

  defp reduce_new_account_opts(_, acc), do: acc

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

    payload =
      opts
      |> Enum.reduce(%{}, &reduce_new_order_opts/2)
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

  # Convert new_account/2 params to name/format required by API
  defp reduce_new_order_opts({:identifiers, value}, acc) when is_binary(value) do
    Map.put(acc, "identifiers", [%{type: "dns", value: value}])
  end

  defp reduce_new_order_opts({:identifiers, value}, acc) when is_map(value) do
    Map.put(acc, "identifiers", [value])
  end

  defp reduce_new_order_opts({:identifiers, values}, acc) when is_list(values) do
    Map.put(acc, "identifiers", Enum.map(values, &convert_new_order_identifier/1))
  end

  defp reduce_new_order_opts({:not_before, value}, acc) when is_binary(value) do
    Map.put(acc, "notBefore", value)
  end

  defp reduce_new_order_opts({:not_after, value}, acc) when is_binary(value) do
    Map.put(acc, "notAfter", value)
  end

  defp reduce_new_order_opts(_, acc), do: acc

  defp convert_new_order_identifier(value) when is_binary(value) do
    %{type: "dns", value: value}
  end

  defp convert_new_order_identifier(value) when is_map(value) do
    value
  end

  def get_order_challenges(session, authorizations) do
    {session, results} =
      Enum.reduce(authorizations, {session, []},
        fn url, {session, acc} ->
          {:ok, session, result} = AcmeClient.post_as_get(session, url)
          {session, [{url, result.body} | acc]}
        end)
    {:ok, session, Enum.reverse(results)}
  end

  def create_validations(challenge_objects, key) do
    for {_url, %{"challenges" => challenges, "identifier" => %{"value" => domain}}} <- challenge_objects,
      %{"type" => type, "token" => token} <- challenges,
      type == "dns-01"
    do
      {domain, dns_validation(token, key)}
    end
  end

  # def create_order(session, opts) do
  #   {:ok, session, order} = AcmeClient.new_order(session, opts)
  #   {:ok, session, challenges} = AcmeClient.get_order_challenges(session, order)
  # end

  @doc ~S"""
  Set up session then create account."

  Params:

  * account_key: Account key
  * contact: Account owner contact

  ## Examples

    contact = "mailto:admin@example.com"
    {:ok, account_key} = AcmeClient.generate_account_key()
    {:ok, session, account} = AcmeClient.create_account(account_key: account_key, contact: contact)
  """
  @spec create_account(Keyword.t()) :: request_ret()
  def create_account(params) do
    with {:ok, session} <- new_session(),
         {:ok, session} <- new_nonce(session)
    do
      session = %{session | account_key: params[:account_key]}
      default_params = [
        terms_of_service_agreed: true
      ]
      params = Keyword.merge(default_params, params)
      new_account(session, params)
    end
  end

  @spec create_session(Keyword.t()) :: {:ok, Session.t()} | {:error, term()}
  def create_session(params \\ []) do
    account_key =
      case Keyword.fetch(params, :account_key) do
        {:ok, value} ->
          value
        :error ->
          account_key_bin = Application.get_env(@app, :account_key)
          AcmeClient.binary_to_key(account_key_bin)
      end

    account_kid =
      case Keyword.fetch(params, :account_kid) do
        {:ok, value} ->
          value
        :error ->
          Application.get_env(@app, :account_kid)
      end

    {:ok, session} = new_session(account_key: account_key, account_kid: account_kid)
    new_nonce(session)
  end

  @doc "Perform POST-as-GET HTTP call"
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

  @doc ~S"""
  Create Tesla client.

  Options are:

  * base_url: URL of server (optional), default "https://acme-staging-v02.api.letsencrypt.org/directory"

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
    opts_middleware = opts[:middleware] || []
    adapter = opts[:adapter]

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
