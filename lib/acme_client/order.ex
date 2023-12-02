defmodule AcmeClient.Order do
  @moduledoc false
  use Ecto.Schema

  schema "orders" do
    field(:domain, :string)
    field(:identifiers, :string)
    field(:status, :string)
    field(:url, :string)
    field(:private_key, :string)
    field(:cert, :string)
    field(:csr, :string)

    timestamps()
  end

  def changeset(order, params \\ %{}) do
    order
    |> Ecto.Changeset.cast(params, [
      :domain,
      :identifiers,
      :status,
      :url,
      :private_key,
      :cert,
      :csr
    ])
    |> Ecto.Changeset.validate_required([:domain])
  end
end
