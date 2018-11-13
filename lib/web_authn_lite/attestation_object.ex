defmodule WebAuthnLite.AttestationObject do
  @moduledoc """
  Data struct and functions for attestationObject

  https://www.w3.org/TR/webauthn/#sctn-attestation
  """

  alias WebAuthnLite.AuthenticatorData

  defstruct [:auth_data, :fmt, :att_stmt, :raw]

  @type t :: %__MODULE__{
          auth_data: AuthenticatorData.t(),
          fmt: binary,
          att_stmt: binary,
          raw: binary
        }

  @spec decode(base64_url_encoded_attestation_object :: String.t()) ::
          t | {:error, :invalid_format}
  def decode(base64_url_encoded_attestation_object) do
    with raw <- base64_url_encoded_attestation_object |> Base.url_decode64!(padding: false),
         %{"authData" => auth_data_binary, "fmt" => fmt, "attStmt" => att_stmt} <-
           raw |> :cbor.decode(),
         {:ok, auth_data} <-
           auth_data_binary
           |> WebAuthnLite.AuthenticatorData.decode(encoded: false) do
      {:ok, %__MODULE__{auth_data: auth_data, fmt: fmt, att_stmt: att_stmt, raw: raw}}
    else
      _ -> {:error, :invalid_format}
    end
  end
end
