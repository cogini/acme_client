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

  require Logger

  def start_link(args) do
    [id | _rest] = args[:identifiers]
    name = {:via, Registry, {AcmeClient.Registry, id}}
    GenServer.start_link(__MODULE__, args, name: name)
  end

  # GenServer callbacks

  @impl true
  def init(args) do
    poll_interval = args[:poll_interval] || 10_000

    state = %{
      timer: nil,
      poll_interval: poll_interval,
      identifiers: args[:identifiers],
      url: args[:url],
      order: args[:order],
      session: nil,
      cb_mod: args[:cb_mod],
    }

    # {:ok, state}
    {:ok, state, {:continue, :spread}}
  end

  @impl true
  def handle_continue(:spread, state) do
    # Sleep for a random amount of time to spread out the load from multiple
    # polling processes evenly
    Process.sleep(:rand.uniform(state.poll_interval))
    {:ok, timer} = :timer.send_interval(state.poll_interval, :timeout)
    {:noreply, %{state | timer: timer}}
  end

  @impl true
  def handle_info(:timeout, %{order: nil} = state) do
    url = state.url
    Logger.info("#{url}: loading order")
    with {:ok, session} <- AcmeClient.create_session(),
         {:ok, _session, order} <- AcmeClient.get_object(session, url)
    do
      state = %{state | order: order}
      {:noreply, state}
    else
      err ->
        Logger.error("#{url}: error #{inspect(err)}")
        {:noreply, state}
    end
  end

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
  def handle_info(:timeout, %{order: %{"status" => "pending"}} = state) do
    url = state.url
    Logger.info("#{url}: pending, processing authorizations")
    with {:ok, session} <- AcmeClient.create_session(),
         {:ok, session, order} <- AcmeClient.get_object(session, url)
    do
      cb_mod = state.cb_mod
      session = Map.put(session, :cb_mod, cb_mod)
      {_session, authorizations} =
        Enum.reduce(order["authorizations"], {session, []}, &process_authorization/2)
      Logger.info("#{url}: authorizations: #{inspect(authorizations)}")

      apply(cb_mod, :process_authorizations, [order, authorizations])
      # if function_exported?(cb_mod, :process_authorizations, 2) do
      #   apply(cb_mod, :process_authorizations, [order, authorizations])
      # end

      {:noreply, %{state | order: order}}
    else
      err ->
        Logger.error("#{url}: error #{inspect(err)}")
        {:noreply, state}
    end
  end

  def handle_info(:timeout, %{order: %{"status" => "ready"}} = state) do
    url = state.url
    Logger.info("#{url}: ready, finalizing")
    with {:ok, session} <- AcmeClient.create_session(),
         {:ok, session, order} <- AcmeClient.get_object(session, url),
         {:ok, _session, _result} <- AcmeClient.poke_url(session, order["finalize"])
    do
      {:noreply, %{state | order: order}}
    else
      err ->
        Logger.error("#{url}: error #{inspect(err)}")
        {:noreply, state}
    end
  end

  def handle_info(:timeout, %{order: %{"status" => "processing"}} = state) do
    url = state.url
    Logger.info("#{url}: processing, polling until valid")
    with {:ok, session} <- AcmeClient.create_session(),
         {:ok, _session, order} <- AcmeClient.get_object(session, url)
    do
      {:noreply, %{state | order: order}}
    else
      err ->
        Logger.error("#{url}: error #{inspect(err)}")
        {:noreply, state}
    end
  end

  def handle_info(:timeout, %{order: %{"status" => "valid"} = order} = state) do
    url = state.url
    Logger.info("#{url}: valid, downloading cert")
    with {:ok, session} <- AcmeClient.create_session(),
         {:ok, _session, certificate} <- AcmeClient.get_object(session, order["certificate"])
    do
      Logger.debug("certificate: #{certificate}")
      cb_mod = state.cb_mod
      apply(cb_mod, :process_certificate, [order, certificate])
      # TODO: this doesn't work for some reason
      # if function_exported?(cb_mod, :process_certificate, 2) do
      #   apply(cb_mod, :process_certificate, [order, certificate])
      # end
      {:stop, :normal, state}
    else
      err ->
        Logger.error("#{url}: error #{inspect(err)}")
        {:noreply, state}
    end
  end

  def handle_info(:timeout, %{order: %{"status" => status}} = state) do
    url = state.url
    Logger.debug("#{url}: #{status}")
    with {:ok, session} <- AcmeClient.create_session(),
         {:ok, _session, order} <- AcmeClient.get_object(session, url)
    do
      {:noreply, %{state | order: order}}
    else
      err ->
        Logger.error("#{url}: error #{inspect(err)}")
        {:noreply, state}
    end
  end

  # TODO: handle status = invalid

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
              {:error, session, reason} ->
                Logger.error("#{domain}: Error poking #{url}: #{inspect(reason)}")
            end
          else
            Logger.info("#{domain}: DNS challenge response not found for #{host}")
          end
          {session, [challenge | challenges]}
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

  # {
  # "identifier": {
  #   "type": "dns",
  #   "value": "cogini.com"
  # },
  # "status": "pending",
  # "expires": "2021-07-12T20:22:34Z",
  # "challenges": [
  #   {
  #     "type": "http-01",
  #     "status": "pending",
  #     "url": "https://acme-staging-v02.api.letsencrypt.org/acme/chall-v3/82803238/qHUWvA",
  #     "token": "XI8WzFHrvnslnoc9JXLjACJCFhcw3PTOmCeCqGn9MME"
  #   },
  #   {
  #     "type": "dns-01",
  #     "status": "pending",
  #     "url": "https://acme-staging-v02.api.letsencrypt.org/acme/chall-v3/82803238/21s6lw",
  #     "token": "XI8WzFHrvnslnoc9JXLjACJCFhcw3PTOmCeCqGn9MME"
  #   },
  #   {
  #     "type": "tls-alpn-01",
  #     "status": "pending",
  #     "url": "https://acme-staging-v02.api.letsencrypt.org/acme/chall-v3/82803238/pgQgNg",
  #     "token": "XI8WzFHrvnslnoc9JXLjACJCFhcw3PTOmCeCqGn9MME"
  #   }
  # ]
end
