![test workflow](https://github.com/cogini/acme_client/actions/workflows/test.yml/badge.svg)
[![Contributor Covenant](https://img.shields.io/badge/Contributor%20Covenant-2.1-4baaaa.svg)](CODE_OF_CONDUCT.md)

# acme_client

Elixir client for the ACME certificate management protocol
[RFC8555](https://tools.ietf.org/html/rfc8555) used by
[Let's Encrypt](https://letsencrypt.org/) and other certification authorities.

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

The pattern is to create a session, call the `newNonce` API to get an initial
nonce, then call one or more APIs to do the work. Functions in this library
keep track of the nonce in the session. So you make a an API call with a
session parameter, then use the returned session to make the next call.

### Accounts

To make API calls, you need to first generate a cryptographic account key,
`account_key` for the client. You then create an account on the server,
identified by an account key id, `account_kid`, a URL on the server.

Generate an account key:

```elixir
{:ok, account_key} = AcmeClient.generate_account_key()
```

The `account_key` is a struct. After generating it, you would normally put it
into the application environment. The following functions convert the struct to
and from a binary string.

```elixir
# Convert key struct into string
account_key_bin = AcmeClient.key_to_binary(account_key)

# Convert string to key struct
account_key_bin = Application.get_env(:acme_client, :account_key)
account_key = AcmeClient.binary_to_key(account_key_bin)
```

Create an account on the ACME service:

```elixir
opts = [
  account_key: account_key,
  contact: "mailto:jake@example.com",
  terms_of_service_agreed: true,
]

{:ok, session} = AcmeClient.new_session(account_key: account_key)
{:ok, session} = AcmeClient.new_nonce(session)
{:ok, session, account} = AcmeClient.new_account(session, opts)
%{url: account_kid} = account
```

### Sessions

`AcmeClient.create_session/1` is a convenience function which creates a session
and gets the initial nonce.

```elixir
{:ok, session} = AcmeClient.create_session(account_key: account_key, account_kid: account_kid)
```

If you call it with no parameters, it reads them from the application environment.

```elixir
{:ok, session} = AcmeClient.create_session(account_key: account_key, account_kid: account_kid)
```

### Orders

Call `AcmeClient.new_order/2` to create an "order" for a certificate.
`account_key` and `account_kid` must be set in the session.

```elixir
{:ok, session, order} = AcmeClient.new_order(session, identifiers: ["example.com", "*.example.com"])
%{url: order_url} = order
```

The `identifiers` key is a domain or list of domains, either binary value or
type/value map.

On success, it returns a map where `url` is the URL of the created order and
`object` has its attributes. Make sure to keep track of the URL, or it may be
impossible to complete the order. The Let's Encrypt API does not support the
ability to get the outstanding orders for an acount, as specified in RFC8555.

### Authorizations

The order response has an "authorization" URL for each domain name.
We call these URLs to create challenge responses.

```elixir
{:ok, session, authorizations} = AcmeClient.create_challenge_responses(session, order.object)
```

A challenge response is a way to prove ownership of the domain.
This library supports two mechanisms, DNS and HTTP.

For DNS, you create a DNS TXT record with the response to the challenge, and the ACME service
will do a lookup to verify that the response it is expecting is there.

```
_acme-challenge.www.example.com. 300 IN TXT <response>
```

For HTTP, the ACME service will make an HTTP request to your web server at a "well known" URL,
and verify that the response is there.

```
http://example.com/.well-known/acme-challenge/<response>
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

For DNS validation, get the `dns-01` responses in DNS format:

```elixir
for {_authorization, %{"identifier" => identifier, "challenges" => challenges}} <- authorizations,
    %{"type" => "dns-01", "response" => response} <- challenges
do
  {AcmeClient.dns_challenge_name(identifier), response}
end

[
  {"_acme-challenge.example.com", "OVO9-UEgCnCE-CEYj7hpC2_gy05Ml66bIJFmU3fnBWs"},
  {"_acme-challenge.example.com", "ySf4juzz6S-QpB3n-5GmfElp-u0r1KJ9kgr8IQwXRSw"}
]
```

Create DNS `TXT` records.

For HTTP validation, get the `http-01` responses:

```elixir
for {_authorization, %{"identifier" => %{"value" => domain}, "challenges" => challenges}} <- authorizations,
    %{"type" => "http-01", "response" => response, "token" => token} <- challenges
do
  {"http://#{domain}" <> AcmeClient.http_challenge_url(token), response}
end
[
  {"http://example.com/.well-known/acme-challenge/HlCVDL_pvaxRQCnRPuo1Ho3BB2TLVUdtpF1Eq1w1yO4",
   "HlCVDL_pvaxRQCnRPuo1Ho3BB2TLVUdtpF1Eq1w1yO4.n044yF8YRKXAnnngt4DzcvUvIN-Wqqn_QtnEhxwGK7g"}
]
```

Add `AcmeClient.Plug` to your Phoenix Endpoint.

```elixir
plug AcmeClient.Plug, /var/lib/foo/acme-client/http_challenge_responses.bert
```

Documentation can be found at [https://hexdocs.pm/acme_client](https://hexdocs.pm/acme_client).

Differences between RFC8555 and Let's Encrypt implementation:
https://github.com/letsencrypt/boulder/blob/master/docs/acme-divergences.md
