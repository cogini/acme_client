defmodule AcmeClient.Application do
  @moduledoc false

  use Application

  @impl true
  def start(_type, _args) do
    children = [
      # Starts a worker by calling: AcmeClient.Worker.start_link(arg)
      # {AcmeClient.Worker, arg}
    ]

    opts = [strategy: :one_for_one, name: AcmeClient.Supervisor]
    Supervisor.start_link(children, opts)
  end
end
