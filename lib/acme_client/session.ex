defmodule AcmeClient.Session do
  @moduledoc """
  This stores information about the current session.
  """

  defstruct [
    account_key: nil,
    account_kid: nil,
    client: nil,
    nonce: nil,
    directory: nil, # url map
    cb_mod: nil,
  ]

  @type t :: %__MODULE__{
    account_key: JOSE.JWK.t() | nil,
    account_kid: binary() | nil,
    client: Tesla.Client.t() | nil,
    nonce: binary() | nil,
    directory: map() | nil,
    cb_mod: module() | nil,
  }
end
