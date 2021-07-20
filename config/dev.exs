use Mix.Config

config :tesla, adapter: Tesla.Adapter.Hackney

config :acme_client,
  # directory_url: "https://acme-staging-v02.api.letsencrypt.org/directory",
  account_kid: "https://acme-staging-v02.api.letsencrypt.org/acme/acct/20177848",
  account_key: "{\"alg\":\"ES256\",\"crv\":\"P-256\",\"d\":\"x6jI_MoOzAChooOJaayBNXXE_wviurtWSsnoYUFnKL0\",\"kty\":\"EC\",\"use\":\"sig\",\"x\":\"AR0XIoSZ9zJnV-V_SHIdL9cmgPdyQqyzUW6SzSPfedQ\",\"y\":\"jzqO48YDlXfGEf4AEBf3zhN6vTc0aYFlGxzmYapY0Nw\"}"
  # prod
  # directory_url: "https://acme-v02.api.letsencrypt.org/directory",
  # directory: %{"keyChange" => "https://acme-v02.api.letsencrypt.org/acme/key-change", "meta" => %{"caaIdentities" => ["letsencrypt.org"], "termsOfService" => "https://letsencrypt.org/documents/LE-SA-v1.2-November-15-2017.pdf", "website" => "https://letsencrypt.org"}, "newAccount" => "https://acme-v02.api.letsencrypt.org/acme/new-acct", "newNonce" => "https://acme-v02.api.letsencrypt.org/acme/new-nonce", "newOrder" => "https://acme-v02.api.letsencrypt.org/acme/new-order", "revokeCert" => "https:/  /acme-v02.api.letsencrypt.org/acme/revoke-cert", "tNtPFfcQemQ" => "https://community.letsencrypt.org/t/adding-random-entries-to-the-directory/33417"}
