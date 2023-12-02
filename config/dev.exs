import Config

config :tesla, adapter: Tesla.Adapter.Hackney

config :acme_client,
  directory_url: System.get_env("DIRECTORY_URL") || "https://acme-staging-v02.api.letsencrypt.org/directory",
  account_key: System.get_env("ACCOUNT_KEY"),
  account_kid: System.get_env("ACCOUNT_KID")
