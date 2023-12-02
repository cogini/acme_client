defmodule AcmeClient.Plug do
  @moduledoc """
  Handle ACME /.well-known/acme-challenge/ requests
  """
  import Logger
  import Plug.Conn

  def init(path) when is_binary(path), do: path

  def call(%Plug.Conn{request_path: "/.well-known/acme-challenge/" <> challenge} = conn, path) do
    if File.exists?(path) do
     case File.read(path) do
      {:ok, data} ->
        responses = :erlang.binary_to_term(data)

        case Map.fetch(responses, challenge) do
          {:ok, response} ->
            Logger.debug("ACME HTTP challenge response: #{inspect(challenge)} #{inspect(response)}")

            conn
            |> put_resp_content_type("application/octet-stream")
            |> send_resp(200, response)
            |> halt()

          :error ->
            Logger.warning("ACME HTTP response not found for challenge: #{inspect(challenge)})
            return_404(conn)
        end

      {:error, reason} ->
        Logger.warning("ACME HTTP challenge response error: #{inspect(reason)}")
        return_404(conn)
     end
    else
      Logger.warning("ACME HTTP challenge response file missing: #{inspect(path)}")
      return_404(conn)
    end
  end

  defp return_404(conn) do
    conn
    |> put_resp_content_type("text/plain")
    |> resp(404, "Not Found")
    |> halt()
  end
end
