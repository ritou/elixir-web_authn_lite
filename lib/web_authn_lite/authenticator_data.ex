defmodule WebAuthnLite.AuthenticatorData do
  @moduledoc """
  Data struct and functions for AuthenticatorData

  https://www.w3.org/TR/webauthn/#authenticator-data
  """
  alias WebAuthnLite.AuthenticatorData.Flags
  alias WebAuthnLite.AttestedCredentialData

  defstruct [:rp_id_hash, :flags, :sign_count, :raw, :attested_credential_data, :extensions]

  @type t :: %__MODULE__{
          rp_id_hash: String.t(),
          flags: binary,
          sign_count: Integer.t(),
          raw: String.t(),
          attested_credential_data: binary,
          extensions: binary
        }

  @min_size_of_authenticator_data 37

  @rounded_error {:error, :invalid_authenticator_data}

  @spec decode(authenticator_data :: String.t()) ::
          {:ok, t} | {:error, :invalid_authenticator_data} | {:error, term}
  def decode(authenticator_data) do
    authenticator_data
    |> Base.url_decode64!(padding: false)
    |> from_binary()
  end

  @spec from_binary(authenticator_data :: binary) ::
          {:ok, t} | {:error, :invalid_authenticator_data} | {:error, term}
  def from_binary(authenticator_data) do
    try do
      with raw <- authenticator_data,
           true <- raw |> byte_size() >= @min_size_of_authenticator_data,
           rp_id_hash <- raw |> :binary.part(0, 32),
           flags <- raw |> :binary.part(32, 1) |> Flags.from_binary() |> elem(1),
           sign_count <- raw |> :binary.part(33, 4) |> :binary.decode_unsigned() do
        attested_credential_data =
          if flags.at && !flags.ed,
            do:
              raw
              |> :binary.part(37, byte_size(raw) - 37)
              |> AttestedCredentialData.from_binary()
              |> elem(1),
            else: nil

        extensions =
          if !flags.at && flags.ed, do: raw |> :binary.part(37, byte_size(raw) - 37), else: nil

        {:ok,
         %__MODULE__{
           rp_id_hash: rp_id_hash |> Base.url_encode64(padding: false),
           flags: flags,
           sign_count: sign_count,
           raw: raw,
           attested_credential_data: attested_credential_data,
           extensions: extensions
         }}
      else
        {:error, _} = error -> error
        _ -> @rounded_error
      end
    rescue
      _ -> @rounded_error
    end
  end

  @spec valid_rp_id_hash?(rp_id :: String.t(), base64_url_encoded_rp_id_hash :: String.t()) ::
          boolean
  def valid_rp_id_hash?(rp_id, base64_url_encoded_rp_id_hash) do
    :crypto.hash(:sha256, rp_id) |> Base.url_encode64(padding: false) ==
      base64_url_encoded_rp_id_hash
  end
end
