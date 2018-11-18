defmodule WebAuthnLite.AttestationObject do
  @moduledoc """
  Data struct and functions for attestationObject

  https://www.w3.org/TR/webauthn/#sctn-attestation

  TODO:
  * Handling AttestationStatement
  """

  alias WebAuthnLite.AuthenticatorData

  defstruct [:auth_data, :fmt, :att_stmt, :raw]

  @type t :: %__MODULE__{
          auth_data: AuthenticatorData.t(),
          fmt: binary,
          att_stmt: binary,
          raw: binary
        }

  @rounded_error {:error, :invalid_attestation_object}

  @spec decode(base64_url_encoded_attestation_object :: String.t()) ::
          {:ok, t} | {:error, :invalid_attestation_object}
  def decode(base64_url_encoded_attestation_object) do
    try do
      with raw <- base64_url_encoded_attestation_object |> Base.url_decode64!(padding: false),
           %{"authData" => auth_data_binary, "fmt" => fmt, "attStmt" => att_stmt} <-
             raw |> :cbor.decode(),
           {:ok, auth_data} <-
             auth_data_binary
             |> WebAuthnLite.AuthenticatorData.from_binary() do
        # TODO: handling attestation statement
        {:ok, %__MODULE__{auth_data: auth_data, fmt: fmt, att_stmt: att_stmt, raw: raw}}
      else
        {:error, _} = error -> error
        _ -> @rounded_error
      end
    rescue
      _ -> @rounded_error
    catch
      # for :cbor.decode failed
      _ ->
        @rounded_error
    end
  end
end
