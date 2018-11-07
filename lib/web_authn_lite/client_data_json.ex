defmodule WebAuthnLite.ClientDataJSON do
  @moduledoc """
  ClientDataJSON Parser
  """

  defstruct [:type, :origin, :challenge, :raw]

  @type t :: %__MODULE__{
          type: String.t(),
          origin: String.t(),
          challenge: String.t(),
          raw: String.t()
        }

  @doc """
  decode Base64 URL encoded clientDataJSON and return struct.
  """
  @spec decode(base64_url_encoded_client_data_json :: String.t()) ::
          {:ok, t} | {:error, :invalid_format}
  def decode(base64_url_encoded_client_data_json) do
    try do
      with raw <- base64_url_encoded_client_data_json |> Base.url_decode64!(padding: false),
           json <- raw |> Jason.decode!() do
        {:ok,
         %__MODULE__{
           type: json["type"],
           origin: json["origin"],
           challenge: json["challenge"],
           raw: raw
         }}
      end
    rescue
      _ -> {:error, :invalid_format}
    end
  end

  @doc """
  validate Base64 URL encoded clientDataJSON with params and return struct.
  """
  @spec validate(
          base64_url_encoded_client_data_json :: String.t(),
          type :: String.t(),
          origin :: String.t(),
          challenge :: String.t()
        ) ::
          {:ok, t}
          | {:error, :invalid_format}
          | {:error, :invalid_type}
          | {:error, :invalid_origin}
          | {:error, :invalid_challenge}
  def validate(base64_url_encoded_client_data_json, type, origin, challenge) do
    with {:ok, client_data} <- decode(base64_url_encoded_client_data_json) do
      cond do
        client_data.type != type -> {:error, :invalid_type}
        client_data.origin != origin -> {:error, :invalid_origin}
        client_data.challenge != challenge -> {:error, :invalid_challenge}
        true -> {:ok, client_data}
      end
    else
      error -> error
    end
  end
end
