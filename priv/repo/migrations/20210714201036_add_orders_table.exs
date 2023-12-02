defmodule AcmeClient.Repo.Migrations.AddOrdersTable do
  use Ecto.Migration

  def change do
    # create table("orders", primary_key: false) do
    #   add :domain, :string, primary_key: true, null: false 
    create table("orders") do
      add :domain, :string, null: false 
      add :identifiers, :string
      add :status, :string 
      add :url, :string
      add :private_key, :string
      add :cert, :string
      add :csr, :string

      # timestamps(updated_at: false)
      timestamps()
    end

    create index("orders", [:domain], unique: true)
  end
end
