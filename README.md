![test workflow](https://github.com/cogini/acme_client/actions/workflows/test.yml/badge.svg)
[![Contributor Covenant](https://img.shields.io/badge/Contributor%20Covenant-2.1-4baaaa.svg)](CODE_OF_CONDUCT.md)

# acme_client

Elixir client for the ACME certificate management protocol
[RFC8555](https://tools.ietf.org/html/rfc8555) used by
[Let's Encrypt](https://letsencrypt.org/) and other certification authorities.

This library was designed for bulk registration, and it supports HTTP and DNS
authorization. It has been used to register millions of certificates.

## Installation

Add `acme_client` to the list of dependencies in `mix.exs`:

```elixir
def deps do
  [
    {:acme_client, "~> 0.1.0"}
  ]
end
```

## Usage

One tricky thing about the ACME API is that it is paranoid about replay
attacks. Every request that you make to the API needs to have a unique nonce.
Every response from the API has a new nonce, passed in a header.

First create a session, then call the `newNonce` API to get an initial
nonce. Use that nonce when calling the API. Take the nonce from that API response
and use it to call another API function, and so on.

Functions in this library keep track of the nonce in the session. Make a an API
call with a session parameter, then use the returned session to make the next
call.

### Accounts

Before making API calls, you first need to generate a cryptographic account key
(`account_key`). You then create an account on the server, identified by an
account key id, `account_kid`, a URL on the server.

Generate an account key:

```elixir
{:ok, account_key} = AcmeClient.generate_account_key()
```

The `account_key` is a struct. After generating it, you would normally save
it as a secret for your app as a string. The following functions convert the
struct to and from a binary string.

```elixir
# Convert key struct to string
account_key_bin = AcmeClient.key_to_binary(account_key)

# Convert string to key struct
account_key_bin = Application.get_env(:acme_client, :account_key)
account_key = AcmeClient.binary_to_key(account_key_bin)
```

Create an account on the ACME service:

```elixir
session_opts = [
  account_key: account_key,
  contact: "mailto:jake@example.com",
  terms_of_service_agreed: true,
]

{:ok, session} = AcmeClient.new_session(account_key: account_key)
{:ok, session} = AcmeClient.new_nonce(session)
{:ok, session, account} = AcmeClient.new_account(session, session_opts)
%{url: account_kid} = account
```

Now save the `account_kid` URL as a config parameter for your app.

### Sessions

`AcmeClient.create_session/1` is a convenience function which creates a session
and gets the initial nonce.

```elixir
{:ok, session} = AcmeClient.create_session(account_key: account_key, account_kid: account_kid)
```

If you call it with no parameters, it reads them from the application environment, e.g.:

```elixir
config :acme_client,
  directory_url:
    System.get_env("ACME_CLIENT_DIRECTORY_URL") ||
      "https://acme-staging-v02.api.letsencrypt.org/directory",
  account_key: System.get_env("ACME_CLIENT_ACCOUNT_KEY"),
  account_kid: System.get_env("ACME_CLIENT_ACCOUNT_KID")

{:ok, session} = AcmeClient.create_session()
```

### Orders

Call `AcmeClient.new_order/2` to create an "order" for a certificate, i.e., a new certificate.
`account_key` and `account_kid` must be set in the session by calling `AcmeClient.create_session()`.

```elixir
{:ok, session, order} = AcmeClient.new_order(session, identifiers: ["example.com", "*.example.com"])
%{url: order_url} = order
```

The `identifiers` key is a domain or list of domains. Values can be either a
binary value or type/value map, e.g., `%{type: "dns", value: "example.com"}`.
Here we are making an order for a cert with both the base domain `example.com`
and the wildcard `*.example.com`. Note that wildcard certs only work with DNS
validation.

On success, it returns a map where `url` is the URL of the created order and
`object` has its attributes. Make sure to keep track of the URL, or it may be
impossible to complete the order, as the Let's Encrypt API does not support the
RFC8555 API functions to get the outstanding orders for an acount.

### Authorizations

The order response has an authorization URL for each domain name in the cert.
The authorization manages challenge responses which are used to prove that you
control the domain.

Next, create challenge responses from the order:

```elixir
{:ok, session, authorizations} = AcmeClient.create_challenge_responses(session, order.object)
```

The `authorizations` response looks like this:

```
[
  {"https://acme-staging-v02.api.letsencrypt.org/acme/authz-v3/9808703214",
   %{
     "challenges" => [
       %{
         "response" => "OVO9-UEgCnCE-CEYj7hpC2_gy05Ml66bIJFmU3fnBWs",
         "status" => "pending",
         "token" => "pYbfjFiJ7L_1DuY3Ms08dCRCFDe97QtsIUj4YNOJrt0",
         "type" => "dns-01",
         "url" => "https://acme-staging-v02.api.letsencrypt.org/acme/chall-v3/9808703214/Ql5IRA"
       }
     ],
     "expires" => "2023-12-09T02:03:19Z",
     "identifier" => %{"type" => "dns", "value" => "example.com"},
     "status" => "pending",
     "wildcard" => true
   }},
  {"https://acme-staging-v02.api.letsencrypt.org/acme/authz-v3/9808703224",
   %{
     "challenges" => [
       %{
         "response" => "HlCVDL_pvaxRQCnRPuo1Ho3BB2TLVUdtpF1Eq1w1yO4.n044yF8YRKXAnnngt4DzcvUvIN-Wqqn_QtnEhxwGK7g",
         "status" => "pending",
         "token" => "HlCVDL_pvaxRQCnRPuo1Ho3BB2TLVUdtpF1Eq1w1yO4",
         "type" => "http-01",
         "url" => "https://acme-staging-v02.api.letsencrypt.org/acme/chall-v3/9808703224/9bBUqQ"
       },
       %{
         "response" => "ySf4juzz6S-QpB3n-5GmfElp-u0r1KJ9kgr8IQwXRSw",
         "status" => "pending",
         "token" => "HlCVDL_pvaxRQCnRPuo1Ho3BB2TLVUdtpF1Eq1w1yO4",
         "type" => "dns-01",
         "url" => "https://acme-staging-v02.api.letsencrypt.org/acme/chall-v3/9808703224/xc7_MA"
       },
       %{
         "status" => "pending",
         "token" => "HlCVDL_pvaxRQCnRPuo1Ho3BB2TLVUdtpF1Eq1w1yO4",
         "type" => "tls-alpn-01",
         "url" => "https://acme-staging-v02.api.letsencrypt.org/acme/chall-v3/9808703224/pvUx0Q"
       }
     ],
     "expires" => "2023-12-09T02:03:19Z",
     "identifier" => %{"type" => "dns", "value" => "example.com"},
     "status" => "pending"
   }}
]}
```

This library supports two challenge response mechanisms, DNS and HTTP.

For DNS, create a DNS TXT record with the response to the challenge, and the
ACME service does a lookup to verify that the response it is expecting is
there:

```
_acme-challenge.www.example.com. 300 IN TXT <response>
```

For HTTP, the ACME service makes an HTTP request to your web server at a "well known" URL,
verifying that the response is there.

```
http://example.com/.well-known/acme-challenge/<response>
```

For DNS validation, get the `dns-01` responses in DNS format, then create DNS `TXT` records.

```elixir
for {_authorization_url, %{"identifier" => identifier, "challenges" => challenges}} <- authorizations,
    %{"type" => "dns-01", "response" => response} <- challenges
do
  {AcmeClient.dns_challenge_name(identifier), response}
end

[
  {"_acme-challenge.example.com", "OVO9-UEgCnCE-CEYj7hpC2_gy05Ml66bIJFmU3fnBWs"},
  {"_acme-challenge.example.com", "ySf4juzz6S-QpB3n-5GmfElp-u0r1KJ9kgr8IQwXRSw"}
]
```

For HTTP validation, get the `http-01` responses and configure your web server to return the response
corresponding to the request.

```elixir
for {_authorization_url, %{"identifier" => %{"value" => domain}, "challenges" => challenges}} <- authorizations,
    %{"type" => "http-01", "response" => response, "token" => token} <- challenges
do
  {"http://#{domain}" <> AcmeClient.http_challenge_url(token), response}
end
[
  {"http://example.com/.well-known/acme-challenge/HlCVDL_pvaxRQCnRPuo1Ho3BB2TLVUdtpF1Eq1w1yO4",
   "HlCVDL_pvaxRQCnRPuo1Ho3BB2TLVUdtpF1Eq1w1yO4.n044yF8YRKXAnnngt4DzcvUvIN-Wqqn_QtnEhxwGK7g"}
]
```

For HTTP validation, you can use the provided plug to serve the requests from a file.

Add `AcmeClient.Plug` to your Phoenix Endpoint.

```elixir
plug AcmeClient.Plug, /var/lib/foo/acme-client/http_challenge_responses.bert
```

TODO:

The initial order creation is synchronous, but the remaining steps involve
communicating with the ACME service, waiting for it to take action and become
ready, then taking the next step.

That is handled by starting a `AcmeClient.Poller` process for the order.

From [RFC8555](https://datatracker.ietf.org/doc/html/rfc8555):

Order objects are created in the "pending" state.  Once all of the
authorizations listed in the order object are in the "valid" state, the order
transitions to the "ready" state.  The order moves to the "processing" state
after the client submits a request to the order's "finalize" URL and the CA
begins the issuance process for the certificate.  Once the certificate is
issued, the order enters the "valid" state.  If an error occurs at any of
these stages, the order moves to the "invalid" state.  The order also moves
to the "invalid" state if it expires or one of its authorizations enters a
final state other than "valid" ("expired", "revoked", or "deactivated").

State Transitions for Order Objects:

```
    pending --------------+
       |                  |
       | All authz        |
       | "valid"          |
       V                  |
     ready ---------------+
       |                  |
       | Receive          |
       | finalize         |
       | request          |
       V                  |
   processing ------------+
       |                  |
       | Certificate      | Error or
       | issued           | Authorization failure
       V                  V
     valid             invalid
```

Authorization objects are created in the "pending" state. If one of the
challenges listed in the authorization transitions to the "valid" state, then
the authorization also changes to the "valid" state. If the client attempts
to fulfill a challenge and fails, or if there is an error while the
authorization is still pending, then the authorization transitions to the
"invalid" state. Once the authorization is in the "valid" state, it can
expire ("expired"), be deactivated by the client ("deactivated", see Section
7.5.2), or revoked by the server ("revoked").

State Transitions for Authorization Objects:

```
               pending --------------------+
                  |                        |
Challenge failure |                        |
       or         |                        |
      Error       |  Challenge valid       |
        +---------+---------+              |
        |                   |              |
        V                   V              |
     invalid              valid            |
                            |              |
                            |              |
                            |              |
             +--------------+--------------+
             |              |              |
             |              |              |
      Server |       Client |   Time after |
      revoke |   deactivate |    "expires" |
             V              V              V
          revoked      deactivated      expired
```
Challenge objects are created in the "pending" state. They transition to the
"processing" state when the client responds to the challenge (see Section
7.5.1) and the server begins attempting to validate that the client has
completed the challenge. Note that within the "processing" state, the server
may attempt to validate the challenge multiple times (see Section 8.2).
Likewise, client requests for retries do not cause a state change.  If
validation is successful, the challenge moves to the "valid" state; if
there is an error, the challenge moves to the "invalid" state.

State Transitions for Challenge Objects:

```
        pending
           |
           | Receive
           | response
           V
       processing <-+
           |   |    | Server retry or
           |   |    | client retry request
           |   +----+
           |
           |
Successful  |   Failed
validation  |   validation
 +---------+---------+
 |                   |
 V                   V
valid              invalid
```

State Transitions for Order Objects:

```
 pending --------------+
    |                  |
    | All authz        |
    | "valid"          |
    V                  |
  ready ---------------+
    |                  |
    | Receive          |
    | finalize         |
    | request          |
    V                  |
processing ------------+
    |                  |
    | Certificate      | Error or
    | issued           | Authorization failure
    V                  V
  valid             invalid
```

Documentation can be found at [https://hexdocs.pm/acme_client](https://hexdocs.pm/acme_client).

Differences between RFC8555 and Let's Encrypt implementation:
https://github.com/letsencrypt/boulder/blob/master/docs/acme-divergences.md
