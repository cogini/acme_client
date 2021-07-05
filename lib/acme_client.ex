defmodule AcmeClient do
  @moduledoc """
  Documentation for `AcmeClient`.
  """
  require Logger
  alias AcmeClient.Session

  @type code :: non_neg_integer()
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

  # https://acme-v02.api.letsencrypt.org/directory or
  # https://acme-staging-v02.api.letsencrypt.org/directory

  @doc "Create session"
  @spec new_session(Keyword.t()) :: {:ok, Session.t()} | {:error, term()}
  def new_session(opts \\ []) do
    directory_url = opts[:directory_url] || "https://acme-staging-v02.api.letsencrypt.org/directory"
    opts_middleware = opts[:middleware] || []
    adapter = opts[:adapter]
    session = %Session{
      account_key: opts[:account_key]
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

  # def generate_account_key(params) do
  #   key_size = params[:key_size] || 2048
  #   JOSE.JWK.generate_key({:rsa, key_size})
  # end

  @doc "Generate a cryptographic key for account"
  @spec generate_account_key(Keyword.t()) :: {:ok, JOSE.JWK.t()}
  def generate_account_key(params \\ []) do
    alg = params[:alg] || "ES256"
    {:ok, JOSE.JWS.generate_key(%{"alg" => alg})}
  end

  # @spec new_account(map(), Keyword.t()) :: {:ok, session :: map(), result || map()} | {:error, session :: map(), result :: map()}
  # %{
  # "contact" => ["mailto:jake@cogini.com"],
  # "createdAt" => "2021-01-21T02:25:34.191981376Z",
  # "initialIp" => "123.194.199.220",
  # "key" => %{
  #   "alg" => "ES256",
  #   "crv" => "P-256",
  #   "kty" => "EC",
  #   "use" => "sig",
  #   "x" => "kk1Lezgf2nsLAc2_Is8pP2KGJRTvTBF2EfPpJgRxWuo",
  #   "y" => "iDsb47bohf2_HMTfo5BGwp4PrjGce7jicc7Jix4B5Yg"
  # },
  # "status" => "valid"
  # }
  @spec new_account(Session.t(), Keyword.t()) :: {:ok, Session.t(), map()} | {:error, Session.t(), Tesla.Env.result()}
  def new_account(session, opts) do
    %{client: client, directory: directory, account_key: account_key, nonce: nonce} = session
    url = directory["newAccount"]
    req_headers = [{"content-type", "application/jose+json"}]

    payload =
      opts
      |> Enum.reduce(%{}, &reduce_account_params/2)
      |> Jason.encode!()

    protected = %{"alg" => "ES256", "nonce" => nonce, "url" => url, jwk: to_jwk(account_key)}
    {_, body} = JOSE.JWS.sign(account_key, payload, protected)

    case Tesla.request(client, method: :post, url: url, body: body, headers: req_headers) do
      {:ok, %{status: status, headers: headers} = result} when status in [200, 201] ->
        session = set_nonce(session, headers)
        value = %{
          account: result.body,
          location: :proplists.get_value("location", headers, nil)
        }
        {:ok, session, value}
      {:ok, %{headers: headers} = result} ->
        {:error, set_nonce(session, headers), result}
      {:error, reason} ->
        {:error, reason}
    end
  end

 # %{
 #   "detail" => "must agree to terms of service",
 #   "status" => 400,
 #   "type" => "urn:ietf:params:acme:error:malformed"
 # }

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

  @spec update_nonce(Session.t(), headers()) :: Session.t()
  def update_nonce(session, headers) do
    %{session | nonce: :proplists.get_value("replay-nonce", headers)}
  end

  @spec extract_nonce(headers()) :: binary() | nil
  def extract_nonce(headers) do
    :proplists.get_value("replay-nonce", headers, nil)
  end

  defp reduce_account_params({:contact, value}, acc) when is_list(value) do
    Map.put(acc, "contact", value)
  end
  defp reduce_account_params({:contact, value}, acc) when is_binary(value) do
    Map.put(acc, "contact", [value])
  end
  defp reduce_account_params({:terms_of_service_agreed, true}, acc) do
    Map.put(acc, "termsOfServiceAgreed", true)
  end
  defp reduce_account_params({:external_account_binding, value}, acc) do
    Map.put(acc, "externalAccountBinding", value)
  end
  defp reduce_account_params(_, acc), do: acc

  def to_jwk(account_key) do
    {_modules, public_map} = JOSE.JWK.to_public_map(account_key)
    public_map
  end

  @doc ~S"""
  Create client to talk to server..

  Options are:

  * base_url: URL of server (optional, default "http://localhost:8081")

  ## Examples

      iex> client = AcmeClient.new()
      %Tesla.Client{
        adapter: nil,
        fun: nil,
        post: [],
        pre: [
          {Tesla.Middleware.BaseUrl, :call, ["http://localhost:8081"]},
        ]
      }
  """
  @spec new(Keyword.t()) :: Tesla.Client.t()
  def new(opts \\ []) do
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

  @spec do_get(Tesla.Client.t(), binary()) :: {:ok, map()} | {:error, map()}
  defp do_get(client, url) do
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

  # Set session nonce from server response headers
  @spec set_nonce(Session.t(), headers()) :: Session.t()
  defp set_nonce(session, headers) do
    %{session | nonce: extract_nonce(headers)}
  end

  @doc ~S"""
  Set up session then create account."

  Params:

  * account_key: Account key
  * contact: Account owner contact

  ## Examples

      iex> {:ok, account} = AcmeClient.create_account(contact: "mailto:admin@example.com")
      %Tesla.Client{
        adapter: nil,
        fun: nil,
        post: [],
        pre: [
          {Tesla.Middleware.BaseUrl, :call, ["http://localhost:8081"]},
        ]
      }
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

end
