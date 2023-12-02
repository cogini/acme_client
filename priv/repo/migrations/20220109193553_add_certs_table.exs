defmodule AcmeClient.Repo.Migrations.AddCertsTable do
  use Ecto.Migration

  def change do
    create table(:certs, primary_key: false) do
      add :hash, :string, null: false, primary_key: true
      add :content, :string, null: false
    end
  end
end
