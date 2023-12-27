defmodule AcmeClient.Crypto do
  @moduledoc """
  Cryptography functions for certificates.
  """

  @doc ~S"""
  Convenience function to create Certificate Signing Request and RSA private key for domain.

  Parameters:

  * domain: Domain name without extension (e.g. "example.com")

  Options:

  * domains: Subject Alt Names (optional, default ["example.com", "*.example.com"])
  * key_size: Size of RSA key (optional, default 2048)

  ## Examples
    csr = AcmeClient.Crypto.create_csr("example.com")
    csr = AcmeClient.Crypto.create_csr("example.com", key_size: 2048)
    csr = AcmeClient.Crypto.create_csr("example.com", domains: ["www.example.com"])
  """
  @spec create_csr(binary(), keyword()) :: map()
  def create_csr(domain, opts \\ []) do
    domains = opts[:domains] || [domain, "*." <> domain]
    key_size = opts[:key_size] || 2048
    private_key = new_private_key(key_size)
    csr = new_csr(domains, private_key)

    %{
      domain: domain,
      pkey: private_key_to_pem(private_key),
      csr: X509.CSR.to_pem(csr)
    }
  end

  @doc ~S"""
  Create Certificate Signing Request.

  Parameters:
  * domains: list of domains (Subject Alt Names)

  ## Examples
    private_key = AcmeClient.Crypto.new_private_key(2048)
    csr = AcmeClient.Crypto.new_csr(["example.com", "*.example.com"], private_key)
  """
  @spec new_csr([binary()], X509.PrivateKey.t()) :: X509.CSR.t()
  def new_csr(domains, private_key, opts \\ []) do
    subject = opts[:subject] || {:rdnSequence, []}

    X509.CSR.new(private_key, subject,
      extension_request: [X509.Certificate.Extension.subject_alt_name(domains)]
    )

    # X509.CSR.to_der(csr)
  end

  @doc ~S"""
  Create RSA private key.

  Parameters:
  * size: Size of RSA key

  ## Examples
    private_key = AcmeClient.Crypto.new_private_key(2048)
  """
  @spec new_private_key(non_neg_integer()) :: X509.PrivateKey.t()
  def new_private_key(size), do: X509.PrivateKey.new_rsa(size)

  @doc ~S"""
  Convert RSA private key to PEM format.

  Parameters:
  * private_key: Private key struct

  ## Examples
    private_key_pem = AcmeClient.Crypto.private_key_to_pem(private_key)
  """
  @spec private_key_to_pem(X509.PrivateKey.t()) :: binary()
  def private_key_to_pem(private_key) do
    private_key
    |> X509.PrivateKey.to_pem()
    |> normalize_pem()
  end

  @spec normalize_pem(binary()) :: binary()
  defp normalize_pem(pem) do
    case String.trim(pem) do
      "" -> ""
      pem -> pem <> "\n"
    end
  end

  defp parse_validity({:Validity, {:utcTime, not_before}, {:utcTime, not_after}}) do
    {:ok, {utctime_to_iso8601(not_before), utctime_to_iso8601(not_after)}}
  end

  defp utctime_to_iso8601(value) when is_list(value) do
    utctime_to_iso8601(to_string(value))
  end

  defp utctime_to_iso8601(value) when is_binary(value) do
    <<yy::binary-size(2), mo::binary-size(2), dd::binary-size(2), hh::binary-size(2), mm::binary-size(2),
      ss::binary-size(2), "Z">> = value

    "20#{yy}-#{mo}-#{dd}T#{hh}:#{mm}:#{ss}Z"
  end

  @spec make_cert_chain(binary(), binary(), binary()) :: [map()]
  def make_cert_chain(domain, certificate, pkey) do
    [cert | chain] = String.split(certificate, "\n\n")

    {entries, hashes} = Enum.reduce(chain, {[], []}, &get_cert_hash/2)

    cert = %{
      domain: domain,
      cert: cert,
      pkey: pkey,
      chain: Enum.reverse(hashes)
    }

    entries ++ [cert]
  end

  defp get_cert_hash(content, {entries, hashes}) do
    content = String.trim(content)
    hash = :sha |> :crypto.hash(content) |> Base.encode16()

    case Repo.get(Cert, hash) do
      nil ->
        Logger.info("Adding chain cert: #{hash}")

        Repo.insert!(%Cert{hash: hash, content: content})
        {[%{domain: hash, cert: content} | entries], [hash | hashes]}

      %Cert{content: ^content} ->
        {entries, [hash | hashes]}
    end
  end
end
