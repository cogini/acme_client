import Config

config :acme_client,
  ecto_repos: [AcmeClient.Repo]

config :acme_client, AcmeClient.Repo,
  database: Path.join(System.get_env("ACME_CLIENT_STATE_DIR", "/var/lib/acme-client"), "acme-client.db")

config :logger,
  level: :info

config :logger, :default_formatter,
  format: "$time $metadata[$level] $message\n",
  metadata: [:pid, :module, :function, :line]

import_config "#{config_env()}.exs"
