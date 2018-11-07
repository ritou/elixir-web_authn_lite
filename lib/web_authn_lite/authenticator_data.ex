defmodule WebAuthnLite.AuthenticatorData do
  @moduledoc """
  Authenticator Parser
  """
  alias WebAuthnLite.AuthenticatorData.Flags

  defstruct [:rp_id_hash, :flags, :sign_count, :raw, :attested_credential_data]

  @type t :: %__MODULE__{
          rp_id_hash: String.t(),
          flags: binary,
          sign_count: Integer.t(),
          raw: String.t(),
          attested_credential_data: binary,
        }

  @min_size_of_authenticator_data 37

  @spec decode(base64_url_encoded_authenticator_data :: String.t()) ::
          {:ok, t} | {:error, :invalid_format}
  def decode(base64_url_encoded_authenticator_data) do
    with raw <- base64_url_encoded_authenticator_data |> Base.url_decode64!(padding: false),
         true <- raw |> byte_size() >= @min_size_of_authenticator_data,
         rp_id_hash <- raw |> :binary.part(0, 32),
         flags <- raw |> :binary.part(32, 1) |> Flags.decode() |> elem(1),
         sign_count <- raw |> :binary.part(33, 4) |> :binary.decode_unsigned()
         # TODO: handle attested_credential_data
    do
      {:ok, %__MODULE__{
          rp_id_hash: rp_id_hash |> Base.url_encode64(padding: false),
          flags: flags,
          sign_count: sign_count,
          raw: raw,
          attested_credential_data: nil
        }
      }
    else
      _ -> {:error, :invalid_format}
    end      
  end
end