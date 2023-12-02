defmodule AcmeClient.MixProject do
  use Mix.Project

  @github "https://github.com/cogini/acme_client"
  @version "0.1.0"

  def project do
    [
      app: :acme_client,
      version: @version,
      elixir: "~> 1.13",
      elixirc_paths: elixirc_paths(Mix.env()),
      start_permanent: Mix.env() == :prod,
      aliases: aliases(),
      dialyzer: [
        plt_add_apps: [:public_key, :mix, :ex_unit]
        # plt_add_deps: true,
        # flags: ["-Werror_handling", "-Wrace_conditions"],
        # flags: ["-Wunmatched_returns", :error_handling, :race_conditions, :underspecs],
        # ignore_warnings: "dialyzer.ignore-warnings"
      ],
      test_coverage: [tool: ExCoveralls],
      preferred_cli_env: [
        coveralls: :test,
        "coveralls.detail": :test,
        "coveralls.post": :test,
        "coveralls.html": :test,
        "coveralls.lcov": :test,
        quality: :test,
        "quality.ci": :test
      ],
      description: description(),
      package: package(),
      source_url: @github,
      homepage_url: @github,
      docs: docs(),
      deps: deps()
    ]
  end

  def application do
    [
      extra_applications: [:logger] ++ extra_applications(Mix.env()),
      mod: {AcmeClient.Application, []}
    ]
  end

  defp extra_applications(:dev), do: [:tools, :hackney]
  defp extra_applications(:test), do: [:tools, :hackney]
  defp extra_applications(_), do: []

  defp elixirc_paths(:dev), do: ["lib", "test/support"]
  defp elixirc_paths(:test), do: ["lib", "test/support"]
  defp elixirc_paths(_), do: ["lib"]

  defp deps do
    [
      {:castore, "~> 1.0"},
      {:credo, "~> 1.6", only: [:dev, :test], runtime: false},
      {:dialyxir, "~> 1.2", only: [:dev, :test], runtime: false},
      {:ecto_sql, "~> 3.10"},
      {:ecto_sqlite3, "~> 0.12.0", only: [:dev, :test], runtime: false},
      {:ex_doc, "~> 0.30.0", only: :dev, runtime: false},
      {:ex_rated, "~> 2.1"},
      {:excoveralls, "~> 0.18.0", only: [:dev, :test], runtime: false},
      {:hackney, "~> 1.17", only: [:dev, :test]},
      {:jason, "~> 1.2"},
      {:jose, "~> 1.11"},
      {:junit_formatter, "~> 3.3", only: [:dev, :test], runtime: false},
      {:mix_audit, "~> 2.0", only: [:dev, :test], runtime: false},
      {:opentelemetry_api, "~> 1.1"},
      {:opentelemetry_ecto, "~> 1.0"},
      {:opentelemetry_tesla, "~> 2.3"},
      {:styler, "~> 0.10.0", only: [:dev, :test], runtime: false},
      {:telemetry, "~> 1.0"},
      {:tesla, "~> 1.4"},
      {:x509, "~> 0.8.2"}
    ]
  end

  defp description do
    "Client for ACME certificate management protocol RFC8555"
  end

  defp package do
    [
      description: description(),
      maintainers: ["Jake Morrison"],
      licenses: ["Apache-2.0"],
      links: %{
        "GitHub" => @github,
        "Changelog" =>
          "#{@github}/blob/#{@version}/CHANGELOG.md##{String.replace(@version, ".", "")}"
      }
    ]
  end

  defp docs do
    [
      main: "readme",
      source_url: @github,
      source_ref: @version,
      extras: [
        "README.md",
        "CHANGELOG.md": [title: "Changelog"]
      ],
      # api_reference: false,
      source_url_pattern: "#{@github}/blob/master/%{path}#L%{line}"
    ]
  end

  defp aliases do
    [
      setup: ["deps.get", "ecto.setup"],
      "ecto.setup": ["ecto.create", "ecto.migrate", "run priv/repo/seeds.exs"],
      "ecto.reset": ["ecto.drop", "ecto.setup"],
      test: ["ecto.create --quiet", "ecto.migrate --quiet", "test"],
      quality: [
        "test",
        "format --check-formatted",
        # "credo",
        "credo --mute-exit-status",
        # mix deps.clean --unlock --unused
        "deps.unlock --check-unused",
        # mix deps.update
        # "hex.outdated",
        # "hex.audit",
        "deps.audit",
        "dialyzer --quiet-with-result"
      ],
      "quality.ci": [
        "format --check-formatted",
        "deps.unlock --check-unused",
        # "hex.outdated",
        "hex.audit",
        "deps.audit",
        "credo",
        "dialyzer --quiet-with-result"
      ]
    ]
  end
end
