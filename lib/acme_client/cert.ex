defmodule AcmeClient.Cert do
  @moduledoc false
  require Logger

  @doc ~S"""
  Create RSA private key.

  ## Examples
    private_key = AcmeClient.Cert.new_private_key(2048)
  """
  @spec new_private_key(non_neg_integer) :: X509.PrivateKey.t()
  def new_private_key(size), do: X509.PrivateKey.new_rsa(size)

  @spec private_key_to_pem(X509.PrivateKey.t()) :: String.t()
  def private_key_to_pem(private_key) do
    private_key
    |> X509.PrivateKey.to_pem()
    |> normalize_pem()
  end

  @doc ~S"""
  Create Certificate Signing Request.

  ## Examples
    private_key = AcmeClient.Cert.new_private_key(2048)
    csr = AcmeClient.Cert.new_csr(["example.com", "*.example.com"], private_key)
  """
  @spec new_csr([binary()], X509.PrivateKey.t()) :: X509.CSR.t()
  def new_csr(domains, private_key, opts \\ []) do
    subject = opts[:subject] || {:rdnSequence, []}

    X509.CSR.new(private_key, subject,
      extension_request: [X509.Certificate.Extension.subject_alt_name(domains)]
    )

    # X509.CSR.to_der(csr)
  end

  @spec normalize_pem(String.t()) :: String.t()
  def normalize_pem(pem) do
    case String.trim(pem) do
      "" -> ""
      pem -> pem <> "\n"
    end
  end
end
