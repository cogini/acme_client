use Mix.Config

config :tesla, adapter: Tesla.Adapter.Hackney

config :acme_client,
  account_kid: "https://acme-staging-v02.api.letsencrypt.org/acme/acct/20177848",
  account_key: "{\"alg\":\"ES256\",\"crv\":\"P-256\",\"d\":\"x6jI_MoOzAChooOJaayBNXXE_wviurtWSsnoYUFnKL0\",\"kty\":\"EC\",\"use\":\"sig\",\"x\":\"AR0XIoSZ9zJnV-V_SHIdL9cmgPdyQqyzUW6SzSPfedQ\",\"y\":\"jzqO48YDlXfGEf4AEBf3zhN6vTc0aYFlGxzmYapY0Nw\"}"
