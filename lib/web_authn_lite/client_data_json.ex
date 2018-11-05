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

  @spec decode(base64_url_encoded_client_data_json :: String.t()) ::
          {:ok, t} | {:error, :invalid_format}
  def decode(base64_url_encoded_client_data_json) do
    try do
      with raw <- base64_url_encoded_client_data_json |> Base.url_decode64!(padding: false),
           json <- raw |> Jason.decode!() do
        %__MODULE__{
          type: json["type"],
          origin: json["origin"],
          challenge: json["challenge"],
          raw: raw
        }
      end
    rescue
      _ -> {:error, :invalid_format}
    end
  end
end
