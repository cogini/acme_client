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

    Order status

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

  # use GenServer, restart: :temporary
  @behavior :gen_statem

  require Logger

  def start_link(args) do
    [id | _rest] = args[:identifiers]
    name = {:via, Registry, {AcmeClient.Registry, id}}
    # GenServer.start_link(__MODULE__, args, name: name)
    :gen_statem.start_link(__MODULE__, args, name: name)
  end

  def child_spec(opts) do
    %{
      id: __MODULE__,
      start: {__MODULE__, :start_link, [opts]},
      type: :worker,
      restart: :temporary,
      shutdown: 500
    }
  end

  @impl :gen_statem
  def init(args) do
    url = args[:url]
    poll_interval = args[:poll_interval] || 10_000

    data = %{
      url: url,
      session: nil,
      order: args[:order],
      cb_mod: args[:cb_mod],
      poll_interval: poll_interval,
    }

    # Sleep for a random amount of time to spread the load from multiple
    # polling processes
    timeout = :rand.uniform(poll_interval)

    with {:ok, session} <- AcmeClient.create_session(),
         {:ok, session, order} <- AcmeClient.get_object(session, url)
    do
      data = %{data | session: session, order: order}
      state = order_status_to_state(order)

      {:ok, state, data, [timeout]}
    else
      err ->
        # Assume it's a transient error
        Logger.error("#{url}: error #{inspect(err)}")
        {:ok, :pending, data, [timeout]}
    end
  end

  # Convert order status to gen_statem state
  defp order_status_to_state(%{"status" => "pending"}), do: :pending
  defp order_status_to_state(%{"status" => "ready"}), do: :ready
  defp order_status_to_state(%{"status" => "processing"}), do: :processing
  defp order_status_to_state(%{"status" => "valid"}), do: :valid
  defp order_status_to_state(%{"status" => "invalid"}), do: :invalid

  @impl :gen_statem
  # def callback_mode, do: :handle_event_function
  def callback_mode, do: :state_functions

  # Order objects are created in the "pending" state. Once all of the
  # authorizations listed in the order object are in the "valid" state, the
  # order transitions to the "ready" state.

  # Authorization objects are created in the "pending" state.  If one of the
  # challenges listed in the authorization transitions to the "valid" state, then
  # the authorization also changes to the "valid" state.  If the client attempts to
  # fulfill a challenge and fails, or if there is an error while the authorization
  # is still pending, then the authorization transitions to the "invalid" state.
  # Once the authorization is in the "valid" state, it can expire ("expired"), be
  # deactivated by the client ("deactivated", see Section 7.5.2), or revoked by the
  # server ("revoked").

  def create_session(data) do
    url = data.url
    case AcmeClient.create_session() do
      {:ok, session} ->
        {:keep_state, %{data | session: session}}
      {:error, reason} ->
        Logger.error("Error creating session: #{inspect(reason)}")
        {:keep_state, data, [data.poll_interval]}
    end
  end

  def pending(event_type, event_content, %{session: nil} = data) do
    create_session(data)
  end

  def pending(_event_type, _event_content, data) do
    url = data.url
    Logger.info("#{url}: pending, processing authorizations")

    session = data.session
    with {:ok, session, order} <- AcmeClient.get_object(session, url)
    do
      cb_mod = data.cb_mod
      session = Map.put(session, :cb_mod, cb_mod)

      case order_status_to_state(order) do
        :pending = state ->
          {session, authorizations} =
            Enum.reduce(order["authorizations"], {session, []}, &process_authorization/2)
          Logger.info("#{url}: authorizations: #{inspect(authorizations)}")

          apply(cb_mod, :process_authorizations, [order, authorizations])
          # if function_exported?(cb_mod, :process_authorizations, 2) do
          #   apply(cb_mod, :process_authorizations, [order, authorizations])
          # end

          {:keep_state, %{data | session: session, order: order}, [data.poll_interval]}
        state ->
          # Transition to state matching order
          Logger.info("#{url}: transition to #{state}")
          {:next_state, state, %{data | session: session, order: order}}
      end
    else
      err ->
        Logger.error("#{url}: error #{inspect(err)}")
        {:keep_state, %{data | session: nil}, [data.poll_interval]}
    end
  end

  def ready(event_type, event_content, data) do
    url = data.url
    Logger.info("#{url}: ready, finalizing")

    session = data.session
    with {:ok, session, order} <- AcmeClient.get_object(session, url)
    do
      case order_status_to_state(order) do
        :ready = state ->
          finalize_url = order["finalize"]
          domain = get_domain(order["identifiers"])
          cb_mod = data.cb_mod

          with {:get_csr, {:ok, csr_pem}} <- {:get_csr, apply(cb_mod, :get_csr, [domain])},
               {:from_pem, {:ok, csr}} <- {:from_pem, X509.CSR.from_pem(csr_pem)},
               {:to_der, csr_der} <- {:to_der, X509.CSR.to_der(csr)},
               {:json_encode, {:ok, json}} <- {:json_encode, Jason.encode(%{csr: Base.url_encode64(csr_der)})},
               {:finalize, {:ok, session, result}} <- {:finalize, AcmeClient.post_as_get(session, finalize_url, json)}
          do
              Logger.debug("#{url} csr: #{json}")
              Logger.info("#{url} finalize #{finalize_url} result: #{inspect(result)}")
              {:keep_state, %{data | session: session, order: order}}
          else
            err ->
              Logger.error("#{url}: error #{inspect(err)}")
              {:keep_state, %{data | session: session, order: order}}
          end

        state ->
          # Transition to state matching order
          Logger.info("#{url}: transition to #{state}")
          {:next_state, state, %{data | session: session, order: order}}
      end
    else
      err ->
        Logger.error("#{url}: error #{inspect(err)}")
        {:ok, session} = AcmeClient.create_session()
        {:keep_state, %{data | session: session}, [data.poll_interval]}
    end
  end

  def processing(event_type, event_content, data) do
    url = data.url
    Logger.info("#{url}: processing, polling until valid")

    session = data.session
    with {:ok, session, order} <- AcmeClient.get_object(session, url)
    do
      case order_status_to_state(order) do
        :processing = state ->
          {:keep_state, %{data | session: session, order: order}}
        state ->
          # Transition to state matching order
          Logger.info("#{url}: transition to #{state}")
          {:next_state, state, %{data | session: session, order: order}}
      end
    else
      err ->
        Logger.error("#{url}: error #{inspect(err)}")
        {:ok, session} = AcmeClient.create_session()
        {:keep_state, %{data | session: session}, [data.poll_interval]}
    end
  end

  def valid(event_type, event_content, data) do
    url = data.url
    Logger.info("#{url}: valid, downloading cert")

    # Order will still be valid from caller as this is final state
    order = data.order

    session = data.session
    with {:ok, session, certificate} <- AcmeClient.get_object(session, order["certificate"])
    do
      # Logger.debug("certificate: #{certificate}")
      cb_mod = data.cb_mod
      case apply(cb_mod, :process_certificate, [order, certificate]) do
        :ok ->
          {:stop, :normal, data}
      end
    else
      err ->
        Logger.error("#{url}: error #{inspect(err)}")
        {:ok, session} = AcmeClient.create_session()
        {:keep_state, %{data | session: session}, [data.poll_interval]}
    end
  end

  def invalid(event_type, event_content, data) do
    url = data.url
    Logger.warning("#{url}: invalid order")

    # Order will still be valid from caller as this is final state

    # TODO: handle differently?

    {:stop, :normal, data}
  end

  @spec process_authorization(binary() | map(), {Session.t(), list()}) :: {Session.t(), list()}
  def process_authorization(url, {session, results} = acc) when is_binary(url) do
    case AcmeClient.post_as_get(session, url) do
      {:ok, session, result} ->
        process_authorization(result.body, {session, results})
      err ->
        Logger.error("#{url}: error #{inspect(err)}")
        acc
    end
  end

  def process_authorization(%{"status" => "valid"}, acc) do
    Logger.info("status: valid")
    acc
  end

  def process_authorization(%{"status" => "pending"} = authorization, {session, results} = acc) do
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

  def process_authorization(%{"status" => status}, acc) do
    Logger.warning("authorization status #{status}")
    acc
  end

  def get_domain(identifiers) do
    [domain | _rest] =
      for %{"type" => type, "value" => value} <- identifiers,
        type == "dns", not String.starts_with?(value, "*.") do
          value
      end
    domain
  end
end
