defmodule WebAuthnLite.AttestedCredentialData do
  @moduledoc """
  Data struct and functions for AttestedCredentialData

  https://www.w3.org/TR/webauthn/#sec-attested-credential-data
  """

  alias WebAuthnLite.{CredentialPublicKey, CBOR}

  defstruct [:aaguid, :credential_id, :credential_public_key, :raw]

  @min_size_of_attested_credential_data 18

  @type t :: %__MODULE__{
          aaguid: String.t(),
          credential_id: String.t(),
          credential_public_key: term,
          raw: binary
        }

  @rounded_error {:error, :invalid_attested_credential_data}

  @spec from_binary(attested_credential_data :: binary) ::
          t | {:error, :invalid_attested_credential_data} | {:error, term}
  def from_binary(attested_credential_data) do
    with true <- attested_credential_data |> byte_size() >= @min_size_of_attested_credential_data,
         aaguid <-
           attested_credential_data |> :binary.part(0, 16) |> Base.url_encode64(padding: false),
         credential_id_length <-
           attested_credential_data |> :binary.part(16, 2) |> :binary.decode_unsigned(),
         credential_id <-
           attested_credential_data |> :binary.part(18, credential_id_length)
           |> Base.url_encode64(padding: false),
         credential_public_key <-
           attested_credential_data
           |> :binary.part(
             18 + credential_id_length,
             byte_size(attested_credential_data) - credential_id_length - 18
           )
           |> CBOR.decode!()
           |> CredentialPublicKey.from_cbor_map() do
      {:ok,
       %__MODULE__{
         aaguid: aaguid,
         credential_id: credential_id,
         credential_public_key: credential_public_key,
         raw: attested_credential_data
       }}
    else
      {:error, _} = error -> error
      _ -> @rounded_error
    end
  end
end
