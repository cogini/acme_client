import Config

config :acme_client,
  account_key:
    "{\"alg\":\"ES256\",\"crv\":\"P-256\",\"d\":\"CBbzro67SpHuMdKDvCdWlAGrVa-FPpFQYZWSPwwiO-4\",\"kty\":\"EC\",\"use\":\"sig\",\"x\":\"pZdm5JkVjULRH0RyJFxsc8BIXm0bRMHJBsuaN5aeSIA\",\"y\":\"GUWG_WobuxqZj6xpa3FC8zLIAA5UR0nptG3QO3d2dfM\"}"

config :junit_formatter,
  report_dir: "#{Mix.Project.build_path()}/junit-reports",
  automatic_create_dir?: true,
  print_report_file: true,
  # prepend_project_name?: true,
  include_filename?: true,
  include_file_line?: true
