defmodule AcmeClient.Repo do
  use Ecto.Repo, otp_app: :acme_client, adapter: Ecto.Adapters.SQLite3
end
