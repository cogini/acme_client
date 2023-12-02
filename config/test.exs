import Config

# config :acme_client, AcmeClient.Repo,
#   username: System.get_env("DATABASE_USER") || "postgres",
#   password: System.get_env("DATABASE_PASS") || "postgres",
#   hostname: System.get_env("DATABASE_HOST") || "localhost",
#   database: System.get_env("DATABASE_DB") || "acme_client_test#{System.get_env("MIX_TEST_PARTITION")}",
#   pool: Ecto.Adapters.SQL.Sandbox,
#   pool_size: String.to_integer(System.get_env("POOL_SIZE") || "10")

config :acme_client,
  account_key:
    "{\"alg\":\"ES256\",\"crv\":\"P-256\",\"d\":\"CBbzro67SpHuMdKDvCdWlAGrVa-FPpFQYZWSPwwiO-4\",\"kty\":\"EC\",\"use\":\"sig\",\"x\":\"pZdm5JkVjULRH0RyJFxsc8BIXm0bRMHJBsuaN5aeSIA\",\"y\":\"GUWG_WobuxqZj6xpa3FC8zLIAA5UR0nptG3QO3d2dfM\"}"

config :logger,
  level: :warning,
  always_evaluate_messages: true

config :logger, :default_formatter,
  format: "$time $metadata[$level] $message\n",
  metadata: [:file, :line]

config :tesla, Tesla.Middleware.Logger, debug: false
# Logging configuration is evaluated at compile time, so Tesla must be
# recompiled for the configuration to take effect:
#   mix deps.clean --build tesla
#   mix deps.compile tesla

config :junit_formatter,
  report_dir: "#{Mix.Project.build_path()}/junit-reports",
  automatic_create_dir?: true,
  print_report_file: true,
  # prepend_project_name?: true,
  include_filename?: true,
  include_file_line?: true
