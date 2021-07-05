# acme_client

Elixir client for the ACME certificate management protocol
[RFC8555](https://tools.ietf.org/html/rfc8555) used by
[Let's Encrypt](https://letsencrypt.org/) and other certification authorities.

## Installation

If [available in Hex](https://hex.pm/docs/publish), the package can be installed
by adding `acme_client` to your list of dependencies in `mix.exs`:

```elixir
def deps do
  [
    {:acme_client, "~> 0.1.0"}
  ]
end
```

Documentation can be generated with [ExDoc](https://github.com/elixir-lang/ex_doc)
and published on [HexDocs](https://hexdocs.pm). Once published, the docs can
be found at [https://hexdocs.pm/acme_client](https://hexdocs.pm/acme_client).

  {:ok, account_key} = AcmeClient.generate_account_key()
  {:ok, session, account_data} = AcmeClient.create_account(account_key: account_key, contact: "mailto:jake@cogini.com")
