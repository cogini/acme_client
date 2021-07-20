defmodule AcmeClient.Poller do
  @moduledoc ~S"""
    +-------------------+--------------------------------+--------------+
    | Action            | Request                        | Response     |
    +-------------------+--------------------------------+--------------+
    | Get directory     | GET  directory                 | 200          |
    |                   |                                |              |
    | Get nonce         | HEAD newNonce                  | 200          |
    |                   |                                |              |
    | Create account    | POST newAccount                | 201 ->       |
    |                   |                                | account      |
    |                   |                                |              |
    | Submit order      | POST newOrder                  | 201 -> order |
    |                   |                                |              |
    | Fetch challenges  | POST-as-GET order's            | 200          |
    |                   | authorization urls             |              |
    |                   |                                |              |
    | Respond to        | POST authorization challenge   | 200          |
    | challenges        | urls                           |              |
    |                   |                                |              |
    | Poll for status   | POST-as-GET order              | 200          |
    |                   |                                |              |
    | Finalize order    | POST order's finalize url      | 200          |
    |                   |                                |              |
    | Poll for status   | POST-as-GET order              | 200          |
    |                   |                                |              |
    | Download          | POST-as-GET order's            | 200          |
    | certificate       | certificate url                |              |
    +-------------------+--------------------------------+--------------+

  Order objects are created in the "pending" state.  Once all of the
  authorizations listed in the order object are in the "valid" state,
  the order transitions to the "ready" state.  The order moves to the
  "processing" state after the client submits a request to the order's
  "finalize" URL and the CA begins the issuance process for the
  certificate.  Once the certificate is issued, the order enters the
  "valid" state.  If an error occurs at any of these stages, the order
  moves to the "invalid" state.  The order also moves to the "invalid"
  state if it expires or one of its authorizations enters a final state
  other than "valid" ("expired", "revoked", or "deactivated").

  State Transitions for Order Objects:

    pending --------------+
       |                  |
       | All authz        |
       | "valid"          |
       V                  |
     ready ---------------+
       |                  |
       | Receive          |
       | finalize         |
       | request          |
       V                  |
   processing ------------+
       |                  |
       | Certificate      | Error or
       | issued           | Authorization failure
       V                  V
     valid             invalid


  Authorization objects are created in the "pending" state. If one of the
  challenges listed in the authorization transitions to the "valid" state,
  then the authorization also changes to the "valid" state. If the client
  attempts to fulfill a challenge and fails, or if there is an error while
  the authorization is still pending, then the authorization transitions to
  the "invalid" state. Once the authorization is in the "valid" state, it
  can expire ("expired"), be deactivated by the client ("deactivated", see
  Section 7.5.2), or revoked by the server ("revoked").

  State Transitions for Authorization Objects:

                   pending --------------------+
                      |                        |
    Challenge failure |                        |
           or         |                        |
          Error       |  Challenge valid       |
            +---------+---------+              |
            |                   |              |
            V                   V              |
         invalid              valid            |
                                |              |
                                |              |
                                |              |
                 +--------------+--------------+
                 |              |              |
                 |              |              |
          Server |       Client |   Time after |
          revoke |   deactivate |    "expires" |
                 V              V              V
              revoked      deactivated      expired

  Challenge objects are created in the "pending" state. They transition to
  the "processing" state when the client responds to the challenge (see
  Section 7.5.1) and the server begins attempting to validate that the client
  has completed the challenge. Note that within the "processing" state, the
  server may attempt to validate the challenge multiple times (see Section
  8.2). Likewise, client requests for retries do not cause a state change.
  If validation is successful, the challenge moves to the "valid" state; if
  there is an error, the challenge moves to the "invalid" state.

  State Transitions for Challenge Objects:

             pending
                |
                | Receive
                | response
                V
            processing <-+
                |   |    | Server retry or
                |   |    | client retry request
                |   +----+
                |
                |
     Successful  |   Failed
     validation  |   validation
      +---------+---------+
      |                   |
      V                   V
     valid              invalid


  Create order
  Generate challenge responses
  Create response records
  Create DNS records

  Poll for DNS records to be available
    Timeout

  post-as-get challenge URL with {} telling server it's ready
    Only do this for challenges with status status == pending
  Server will attempt to validate
    Challenge will turn to state == valid, and authorization will turn to state == valid
  Poll order URL for status == ready
  Finalize order with post-as-get to finalize URL with {} telling server it's ready
  Poll order URL for status == valid
  """

  use GenServer, restart: :temporary
  # @behaviour :gen_statem

  require Logger
  alias AcmeClient.Session

  def start_link(args, opts \\ []) do
    # Logger.warning("args: #{inspect(args)}")
    [id | _rest] = args[:identifiers]
    name = {:via, Registry, {AcmeClient.Registry, id}}
    # :gen_statem.start_link(__MODULE__, args, name: name, debug: :log)
    # :gen_statem.start_link(name, __MODULE__, args, [debug: :log])
    # :gen_statem.start_link(name, __MODULE__, args, [[debug: :trace]])
    # :gen_statem.start_link(name, __MODULE__, args, opts)
    opts = Keyword.put_new(opts, :name, name)
    GenServer.start_link(__MODULE__, args, opts)
  end

  # def child_spec(opts) do
  #   %{
  #     id: __MODULE__,
  #     start: {__MODULE__, :start_link, [opts]},
  #     type: :worker,
  #     restart: :temporary,
  #     shutdown: 500
  #   }
  # end

  # @impl :gen_statem
  @impl GenServer
  def init(args) do
    url = args[:url]
    poll_interval = args[:poll_interval] || 10_000

    state = %{
      poll_interval: poll_interval,
      session: nil,
      cb_mod: args[:cb_mod],
      url: url,
      order: args[:order],
      challenge_responses: args[:challenge_responses],
      status: :pending,
      timer: nil,
    }

    Logger.metadata(Keyword.put(Logger.metadata(), :order, url))

    # Spread out load from multiple polling processes
    # timeout = :rand.uniform(poll_interval)

    # with {:ok, session} <- AcmeClient.create_session(),
    #      {:ok, session, order} <- AcmeClient.get_object(session, url)
    # do
    #   data = %{data | session: session, order: order}
    #   state = order_status_to_state(order)
    #
    #   {:ok, state, data, [timeout]}
    # else
    #   err ->
    #     # Assume it's a transient error
    #     Logger.error("#{url}: error #{inspect(err)}")
    #
    #     {:ok, :pending, data, [timeout]}
    # end

    # Spread out load from multiple polling processes
    Process.send_after(self(), :timeout, :rand.uniform(poll_interval))

    # {:ok, :pending, data, [timeout]}
    # {:ok, state, {:continue, :spread}}
    {:ok, state}
  end

  # def handle_continue(:spread, state) do
  #   # Spread out load from multiple polling processes
  #   Process.send_after(self(), :timeout, :rand.uniform(poll_interval))
  #   {:noreply, state}
  #   # {:ok, timer} = :timer.send_interval(state.poll_interval, :timeout)
  #   # {:noreply, %{state | timer: timer}}
  # end

  # Convert order status to gen_statem state
  defp order_status_to_state(%{"status" => "pending"}), do: :pending
  defp order_status_to_state(%{"status" => "ready"}), do: :ready
  defp order_status_to_state(%{"status" => "processing"}), do: :processing
  defp order_status_to_state(%{"status" => "valid"}), do: :valid
  defp order_status_to_state(%{"status" => "invalid"}), do: :invalid

  # @impl :gen_statem
  # def callback_mode, do: :handle_event_function
  # def callback_mode, do: :state_functions
  # def callback_mode, do: [:state_functions, :state_enter]

  # Order objects are created in the "pending" state. Once all of the
  # authorizations listed in the order object are in the "valid" state, the
  # order transitions to the "ready" state.

  def handle_info(:timeout, %{session: nil} = state) do
    case AcmeClient.create_session() do
      {:ok, session} ->
        Logger.info("Creating ACME session")
        # handle_info(:timeout, %{state | session: session})
        {:noreply, %{state | session: session}, 0}
      {:error, reason} ->
        Logger.error("Error creating ACME session: #{inspect(reason)}")
        {:noreply, state, state.poll_interval}
    end
  end

  def handle_info(:timeout, %{status: :pending, challenge_responses: nil} = state) do
    %{url: url, session: session, status: status} = state
    Logger.info("#{status}, processing authorizations)")
    case AcmeClient.get_object(session, url) do
      {:ok, session, order} ->

        id = get_id(order["identifiers"])
        Logger.metadata(Keyword.put(Logger.metadata(), :id, id))

        case order_status_to_state(order) do
          ^status ->
            key = session.account_key
            cb_mod = state.cb_mod

            case get_authorizations(session, order["authorizations"]) do
              {:ok, session, authorizations} ->
                # Logger.debug("#{url}: authorizations #{inspect(authorizations)}")
                responses =
                  authorizations
                  |> Enum.map(fn {_url, auth} -> create_challenge_responses(auth, key) end)
                  |> List.flatten()
                  |> merge_challenge_responses()
                  |> publish_challenge_responses(cb_mod)

                {:noreply, %{state | session: session, challenge_responses: responses}, 0}
              {:error, reason} ->
                Logger.error("get_authorizations error #{inspect(reason)}")
                {:noreply, state, state.poll_interval}
            end

          new_status ->
            Logger.info("Transition to #{inspect(new_status)}")
            {:noreply, %{state | status: new_status}, state.poll_interval}
        end
      err ->
        Logger.error("Error getting object: #{inspect(err)}")
        {:noreply, %{state | session: nil}, state.poll_interval}
    end
  end

  def handle_info(:timeout, %{status: :pending, challenge_responses: challenge_responses} = state) do
    %{url: url, session: session, status: status} = state
    Logger.info("#{status}, processing challenges)")
    case AcmeClient.get_object(session, url) do
      {:ok, session, order} ->
        case order_status_to_state(order) do
          ^status ->

            # Logger.debug("challenge_responses: #{inspect(challenge_responses)}")
            session =
              for {_domain, responses} <- challenge_responses, response <- responses, reduce: session do
                nil -> nil
                session ->
                  %{"domain" => domain, "url" => ready_url, "response" => response_code} = response
                  host = AcmeClient.dns_challenge_name(domain)

                  txt_records = AcmeClient.dns_txt_records(host)
                  # Logger.debug("txt_records for #{host}: #{inspect(txt_records)}")

                  if response_code in txt_records do
                    Logger.info("#{url}: DNS found #{host} #{response_code}")

                    case AcmeClient.poke_url(session, ready_url) do
                      {:ok, session, poke_result} ->
                        Logger.info("#{url}: poked #{ready_url}: #{inspect(poke_result)}")
                        session
                      {:error, session, reason} ->
                        Logger.error("#{url}: #{domain} Error poking #{ready_url}: #{inspect(reason)}")
                        session
                      {:error, reason} ->
                        Logger.error("#{url}: #{domain} Error poking #{ready_url}: #{inspect(reason)}")
                        nil
                    end
                  else
                    Logger.info("#{url}: DNS not found #{host} #{response_code}")
                    session
                  end
              end

            {:noreply, %{state | session: session}, state.poll_interval}

          new_status ->
            Logger.info("Transition to #{inspect(new_status)}")
            {:noreply, %{state | status: new_status}, 0}
        end
      err ->
        Logger.error("Error getting object: #{inspect(err)}")
        {:noreply, %{state | session: nil}, state.poll_interval}
    end
  end

  def handle_info(:timeout, %{status: :ready} = state) do
    %{url: url, session: session, status: status} = state
    Logger.info("#{status}, finalizing")
    case AcmeClient.get_object(session, url) do
      {:ok, session, order} ->
        case order_status_to_state(order) do
          ^status ->

            finalize_url = order["finalize"]
            domain = get_domain(order["identifiers"])
            cb_mod = state.cb_mod

            with {:get_csr, {:ok, csr_pem}} <- {:get_csr, apply(cb_mod, :get_csr, [domain])},
                 {:from_pem, {:ok, csr}} <- {:from_pem, X509.CSR.from_pem(csr_pem)},
                 {:to_der, csr_der} <- {:to_der, X509.CSR.to_der(csr)},
                 {:json_encode, {:ok, json}} <- {:json_encode, Jason.encode(%{csr: Base.url_encode64(csr_der)})},
                 {:finalize, {:ok, session, result}} <- {:finalize, AcmeClient.post_as_get(session, finalize_url, json)}
            do
                Logger.debug("csr: #{json}")
                Logger.info("finalize #{finalize_url} result: #{inspect(result)}")
                {:noreply, %{state | session: session}, 0}
            else
              err ->
                Logger.error("error #{inspect(err)}")
                {:noreply, %{state | session: nil}, state.poll_interval}
            end

          new_status ->
            Logger.info("Transition to #{inspect(new_status)}")
            {:noreply, %{state | status: new_status}, 0}
        end
      err ->
        Logger.error("Error getting object: #{inspect(err)}")
        {:noreply, %{state | session: nil}, state.poll_interval}
    end
  end

  def handle_info(:timeout, %{status: :ready} = state) do
    %{url: url, session: session, status: status} = state
    Logger.info("#{status}, finalizing")
    case AcmeClient.get_object(session, url) do
      {:ok, session, order} ->
        case order_status_to_state(order) do
          ^status ->

            finalize_url = order["finalize"]
            domain = get_domain(order["identifiers"])
            cb_mod = state.cb_mod

            with {:get_csr, {:ok, csr_pem}} <- {:get_csr, apply(cb_mod, :get_csr, [domain])},
                 {:from_pem, {:ok, csr}} <- {:from_pem, X509.CSR.from_pem(csr_pem)},
                 {:to_der, csr_der} <- {:to_der, X509.CSR.to_der(csr)},
                 {:json_encode, {:ok, json}} <- {:json_encode, Jason.encode(%{csr: Base.url_encode64(csr_der)})},
                 {:finalize, {:ok, session, result}} <- {:finalize, AcmeClient.post_as_get(session, finalize_url, json)}
            do
                Logger.debug("csr: #{json}")
                Logger.info("finalize #{finalize_url} result: #{inspect(result)}")
                {:noreply, %{state | session: session}, 0}
            else
              err ->
                Logger.error("error #{inspect(err)}")
                {:noreply, %{state | session: nil}, state.poll_interval}
            end

          new_status ->
            Logger.info("Transition to #{inspect(new_status)}")
            {:noreply, %{state | status: new_status}, 0}
        end
      err ->
        Logger.error("Error getting object: #{inspect(err)}")
        {:noreply, %{state | session: nil}, state.poll_interval}
    end
  end

  def handle_info(:timeout, %{status: :processing} = state) do
    %{url: url, session: session, status: status} = state
    Logger.info("#{status}, polling until valid")
    case AcmeClient.get_object(session, url) do
      {:ok, session, order} ->
        case order_status_to_state(order) do
          ^status ->
            {:noreply, %{state | session: session}, state.poll_interval}
          new_status ->
            Logger.info("Transition to #{inspect(new_status)}")
            {:noreply, %{state | status: new_status}, 0}
        end
      err ->
        Logger.error("Error getting object: #{inspect(err)}")
        {:noreply, %{state | session: nil}, state.poll_interval}
    end
  end

  def handle_info(:timeout, %{status: :valid} = state) do
    %{url: url, session: session, status: status} = state
    Logger.info("#{status}, downloading certificate")
    case AcmeClient.get_object(session, url) do
      {:ok, session, order} ->
        case order_status_to_state(order) do
          ^status ->

            case AcmeClient.get_object(session, order["certificate"]) do
              {:ok, session, certificate} ->
                Logger.debug("certificate: #{certificate}")
                cb_mod = state.cb_mod
                case apply(cb_mod, :process_certificate, [order, certificate]) do
                  :ok ->
                    apply(cb_mod, :ack_order, [order])

                    Logger.info("Stopping")
                    {:stop, :normal, state}
                  _ ->
                    {:noreply, %{state | session: session}, state.poll_interval}
                end
              err ->
                Logger.error("Error reading certificate #{inspect(err)}")
                {:noreply, %{state | session: nil}, state.poll_interval}
            end

          new_status ->
            Logger.info("Transition to #{inspect(new_status)}")
            {:noreply, %{state | status: new_status}, 0}
        end
      err ->
        Logger.error("Error getting object: #{inspect(err)}")
        {:noreply, %{state | session: nil}, state.poll_interval}
    end
  end

  def handle_info(:timeout, %{status: :invalid} = state) do
    %{status: status, order: order} = state
    Logger.warning("#{status}, invalid order")

    cb_mod = state.cb_mod
    apply(cb_mod, :ack_order, [order])

    Logger.info("Stopping")
    # TODO: callback

    {:stop, :normal, state}
  end

  @doc "Get details of order authorizations"
  @spec get_authorizations(Session.t(), [binary()]) :: {:ok, Session.t(), list({binary(), map()})}
                                                     | {:error, term()}
  def get_authorizations(session, urls) do
    result =
      Enum.reduce(urls, {session, []},
        fn
          _url, {nil, results} ->
            {nil, results}
          url, {session, results} ->
            case AcmeClient.post_as_get(session, url) do
              {:ok, session, result} ->
                {session, [{url, result.body} | results]}
              {:error, session, reason} ->
                {session, [{url, {:error, reason}} | results]}
                {:error, reason}
                {nil, [{url, {:error, reason}} | results]}
            end
        end)

    case result do
      {nil, [error | _rest]} ->
          error

      {session, results} ->
        {:ok, session, results}
    end
  end

  # @spec process_authorization(binary() | map(), {Session.t(), list()}) :: {Session.t(), list()}
  # def process_authorization(url, {session, results} = acc) when is_binary(url) do
  #   case AcmeClient.post_as_get(session, url) do
  #     {:ok, session, result} ->
  #       process_authorization(result.body, {session, results})
  #     err ->
  #       Logger.error("#{url}: error reading authorization #{inspect(err)}")
  #       acc
  #   end
  # end

  def process_authorization(%{"status" => "pending"} = authorization, {session, results}) do
    %{"identifier" => %{"type" => "dns", "value" => domain}} = authorization
    Logger.info("authorization: #{inspect(authorization)}")

    process_challenge =
      fn
        %{"status" => "valid", "type" => "dns-01"}, acc -> acc
        %{"status" => "processing", "type" => "dns-01"}, acc -> acc
        %{"status" => "pending", "type" => "dns-01"} = challenge, {session, challenges} ->
          %{"token" => token, "url" => url} = challenge
          response = AcmeClient.dns_challenge_response(token, session.account_key)
          challenge = Map.put(challenge, "response", response)
          Logger.info("challenge: #{inspect(challenge)}")

          host = AcmeClient.dns_challenge_name(domain)
          txt_records = AcmeClient.dns_txt_records(host)

          if response in txt_records do
            case AcmeClient.poke_url(session, url) do
              {:ok, session, poke_result} ->
                Logger.info("#{domain}: poked #{url}: #{inspect(poke_result)}")
                {session, [challenge | challenges]}
              {:error, session, reason} ->
                Logger.error("#{domain}: Error poking #{url}: #{inspect(reason)}")
                {session, [challenge | challenges]}
            end
          else
            Logger.info("#{domain}: DNS challenge response not found for #{host}")
            {session, [challenge | challenges]}
          end
        _, acc -> acc
      end

    {session, challenges} =
        Enum.reduce(authorization["challenges"], {session, []}, process_challenge)

    authorization = Map.put(authorization, "challenges", challenges)
    {session, [authorization | results]}
  end

  def process_authorization(%{"status" => "valid"}, acc) do
    Logger.info("status: valid")
    acc
  end

  def process_authorization(%{"status" => status}, acc) do
    Logger.warning("authorization status #{status}")
    acc
  end

  # def challenge_response(%{"status" => "valid", "type" => "dns-01"}, acc), do: acc
  # def challenge_response(%{"status" => "processing", "type" => "dns-01"}, acc), do: acc
  # def challenge_response(%{"status" => "pending", "type" => "dns-01"}, acc) do
  #   %{"token" => token, "url" => url} = challenge

  #   response = AcmeClient.dns_challenge_response(token, session.account_key)
  #   challenge = Map.put(challenge, "response", response)

  #   Logger.info("challenge: #{inspect(challenge)}")

  #   host = AcmeClient.dns_challenge_name(domain)
  #   txt_records = AcmeClient.dns_txt_records(host)

  #   if response in txt_records do
  #     case AcmeClient.poke_url(session, url) do
  #       {:ok, session, poke_result} ->
  #         Logger.info("#{domain}: poked #{url}: #{inspect(poke_result)}")
  #         {session, [challenge | challenges]}
  #       {:error, session, reason} ->
  #         Logger.error("#{domain}: Error poking #{url}: #{inspect(reason)}")
  #         {session, [challenge | challenges]}
  #     end
  #   else
  #     Logger.info("#{domain}: DNS challenge response not found for #{host}")
  #     {session, [challenge | challenges]}
  #   end
  # end

  def process_challenge(c, {session, results}) do
    {session, [c | results]}
  end

  @spec create_challenge_responses(map(), JOSE.JWK.t()) :: list(map())
  def create_challenge_responses(authorization, key) do
    %{"identifier" => %{"type" => "dns", "value" => domain}} = authorization
    for challenge <- authorization["challenges"],
      challenge["status"] == "pending",
      challenge["type"] == "dns-01"
    do
      response = AcmeClient.dns_challenge_response(challenge["token"], key)

      challenge
      |> Map.take(["type", "token", "url"])
      |> Map.merge(%{"domain" => domain, "response" => response})
      |> Map.merge(Map.take(authorization, ["wildcard"]))
    end
  end

  @doc "If challenge response works, tell server"
  @spec respond_to_challenge(map(), Session.t() | nil) :: Session.t() | nil
  def respond_to_challenge(_challenge, nil), do: nil

  def respond_to_challenge(challenge, session) do
    %{"response" => response, "domain" => domain, "url" => url} = challenge
    host = AcmeClient.dns_challenge_name(domain)
    txt_records = AcmeClient.dns_txt_records(host)

    if response in txt_records do
      case AcmeClient.poke_url(session, url) do
        {:ok, session, poke_result} ->
          Logger.info("#{domain}: poked #{url}: #{inspect(poke_result)}")
          session
        {:error, session, reason} ->
          Logger.error("#{domain}: Error poking #{url}: #{inspect(reason)}")
          session
        {:error, reason} ->
          Logger.error("#{domain}: Error poking #{url}: #{inspect(reason)}")
          nil
      end
    else
      Logger.info("#{domain}: DNS challenge response not found for #{host}")
      session
    end
  end

  @doc "Merge responses with same domain"
  @spec merge_challenge_responses([map()]) :: map()
  def merge_challenge_responses(responses) do
    for %{"domain" => domain} = response <- responses, reduce: %{} do
      acc -> Map.update(acc, domain, [response], fn cur -> [response | cur] end)
    end
  end

  @spec publish_challenge_responses(map(), module() | nil) :: map()
  def publish_challenge_responses(responses, nil), do: responses
  def publish_challenge_responses(responses, cb_mod) do
    apply(cb_mod, :publish_challenge_responses, [responses])
    responses
  end

  def get_domain(identifiers) do
    [domain | _rest] =
      for %{"type" => type, "value" => value} <- identifiers,
        type == "dns", not String.starts_with?(value, "*.") do
          value
      end
    domain
  end

  def get_id(identifiers), do: get_domain(identifiers)

end
