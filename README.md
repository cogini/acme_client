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

Differences between RFC8555 and Let's Encrypt implementation:
https://github.com/letsencrypt/boulder/blob/master/docs/acme-divergences.md

  {:ok, account_key} = AcmeClient.generate_account_key()
  {:ok, session, account_data} = AcmeClient.create_account(account_key: account_key, contact: "mailto:jake@cogini.com")

  account_key_bin = Application.get_env(:acme_client, :account_key)
  account_key = AcmeClient.binary_to_key(account_key_bin)
  {:ok, session} = AcmeClient.new_session(account_key: account_key)
  {:ok, session} = AcmeClient.new_nonce(session)

  {:ok, session, result} = AcmeClient.new_order(session, identifiers: ["cogini.com", "www.cogini.com"])

  {:ok, session, order_result} = AcmeClient.post_as_get(session, "https://acme-staging-v02.api.letsencrypt.org/acme/order/20177848/94029681")
  {:ok, session, challenges} = AcmeClient.get_order_challenges(session, order_result.body["authorizations"])

  AcmeClient.create_validations(challenges, session.account_key)

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

Production

  {:ok, account_key} = AcmeClient.generate_account_key()
  {:ok, session} = AcmeClient.new_session(directory_url: "https://acme-v02.api.letsencrypt.org/directory")
  {:ok, session} = AcmeClient.new_nonce(session)

  {:ok, session, account} = AcmeClient.new_account(session, terms_of_service_agreed: true, account_key: account_key, contact: "mailto:ssl_admin@ptl.com")
