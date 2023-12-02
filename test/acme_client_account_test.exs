defmodule AcmeClient.AccountTest do
  use ExUnit.Case

  describe "encoding and decoding account keys" do
    test "round trip" do
      account_key_bin = Application.get_env(:acme_client, :account_key)
      account_key = AcmeClient.binary_to_key(account_key_bin)
      assert account_key_bin == AcmeClient.key_to_binary(account_key)
    end
  end
end
