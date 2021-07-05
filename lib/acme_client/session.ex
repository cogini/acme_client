defmodule AcmeClient.Session do
  @moduledoc """
  This stores information about the request.
  """

  defstruct [
    account_key: nil,
    client: nil,
    nonce: "",
    directory: %{}, # url map
  ]

  @type t :: %__MODULE__{
    account_key: JOSE.JWK.t(),
    client: Tesla.Client.t(),
    nonce: binary(),
    directory: map(),
  }
end
