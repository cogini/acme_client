defmodule AcmeClient.Session do
  @moduledoc """
  This stores information about the current session.
  """

  defstruct account_key: nil,
            account_kid: nil,
            client: nil,
            nonce: nil,
            # url map
            directory: nil,
            cb_mod: nil,
            # See ExRated
            rate_limit_id: nil,
            rate_limit_scale: nil,
            rate_limit_limit: nil

  @type t :: %__MODULE__{
          account_key: JOSE.JWK.t() | nil,
          account_kid: binary() | nil,
          client: Tesla.Client.t() | nil,
          nonce: binary() | nil,
          directory: map() | nil,
          cb_mod: module() | nil,
          # See ExRated
          rate_limit_id: binary() | nil,
          rate_limit_scale: pos_integer() | nil,
          rate_limit_limit: pos_integer() | nil
        }
end
