defmodule AcmeClient.Session do
  @moduledoc """
  This stores information about the current session.
  """

  defstruct [
    account_key: nil,
    account_kid: nil,
    client: nil,
    nonce: "",
    directory: %{}, # url map
  ]

  @type t :: %__MODULE__{
    account_key: JOSE.JWK.t(),
    account_kid: binary(),
    client: Tesla.Client.t(),
    nonce: binary(),
    directory: map(),
  }
end
