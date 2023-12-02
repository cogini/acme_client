import Config

# config :acme_client, AcmeClient.Repo,
#   username: System.get_env("DATABASE_USER") || "postgres",
#   password: System.get_env("DATABASE_PASS") || "postgres",
#   hostname: System.get_env("DATABASE_HOST") || "localhost",
#   database: System.get_env("DATABASE_DB") || "acme_client_dev",
#   stacktrace: true,
#   show_sensitive_data_on_connection_error: true,
#   pool_size: String.to_integer(System.get_env("POOL_SIZE") || "10")

config :acme_client,
  directory_url:
    System.get_env("ACME_CLIENT_DIRECTORY_URL") || "https://acme-staging-v02.api.letsencrypt.org/directory",
  account_key: System.get_env("ACME_CLIENT_ACCOUNT_KEY"),
  account_kid: System.get_env("ACME_CLIENT_ACCOUNT_KID")

config :logger, :default_formatter,
  format: "$time $metadata[$level] $message\n",
  metadata: [:file, :line]

config :tesla, adapter: Tesla.Adapter.Hackney

# config :tesla, Tesla.Middleware.Logger, debug: false
# Logging configuration is evaluated at compile time, so Tesla must be
# recompiled for the configuration to take effect:
#   mix deps.clean --build tesla
#   mix deps.compile tesla
