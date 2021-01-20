defmodule AcmeClientTest do
  use ExUnit.Case
  doctest AcmeClient

  test "greets the world" do
    assert AcmeClient.hello() == :world
  end
end
