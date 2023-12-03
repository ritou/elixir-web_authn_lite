defmodule WebAuthnLite.AttestedCredentialData do
  @moduledoc """
  Data struct and functions for AttestedCredentialData

  https://www.w3.org/TR/webauthn/#sec-attested-credential-data
  """

  alias WebAuthnLite.CredentialPublicKey

  defstruct [
    :aaguid,
    :authenticator_name,
    :credential_id,
    :credential_public_key,
    :raw,
    :extensions
  ]

  @min_size_of_attested_credential_data 18

  @type t :: %__MODULE__{
          aaguid: String.t(),
          authenticator_name: String.t(),
          credential_id: String.t(),
          credential_public_key: term,
          raw: binary,
          extensions: map | nil
        }

  @rounded_error {:error, :invalid_attested_credential_data}

  # MEMO: aaguid list management
  # Identify the Authenticator Name using publicly available metadata
  # - passkey: https://raw.githubusercontent.com/passkeydeveloper/passkey-authenticator-aaguids/main/aaguid.json
  # - security key: https://mds3.fidoalliance.org/
  @passkey_aaguid_file_name "passkey_aaguid.json"
  @passkey_aaguid_list :code.priv_dir(:web_authn_lite)
                       |> Path.join(@passkey_aaguid_file_name)
                       |> File.read!()
                       |> Jason.decode!()

  @mds_aaguid_file_name "mds_aaguid.json"
  @mds_aaguid_list :code.priv_dir(:web_authn_lite)
                   |> Path.join(@mds_aaguid_file_name)
                   |> File.read!()
                   |> Jason.decode!()

  @unknown_aaguid "00000000-0000-0000-0000-000000000000"

  @spec from_binary(attested_credential_data :: binary) ::
          t | {:error, :invalid_attested_credential_data} | {:error, term}
  def from_binary(attested_credential_data) do
    with true <- attested_credential_data |> byte_size() >= @min_size_of_attested_credential_data,
         aaguid <-
           attested_credential_data |> :binary.part(0, 16) |> format_aaguid(),
         authenticator_name <- lookup_authenticator_name(aaguid),
         credential_id_length <-
           attested_credential_data |> :binary.part(16, 2) |> :binary.decode_unsigned(),
         credential_id <-
           attested_credential_data
           |> :binary.part(18, credential_id_length)
           |> Base.url_encode64(padding: false),
         {:ok, decoded, extensions} <-
           attested_credential_data
           |> :binary.part(
             18 + credential_id_length,
             byte_size(attested_credential_data) - credential_id_length - 18
           )
           |> CBOR.decode(),
         credential_public_key <- decoded |> CredentialPublicKey.from_cbor_map() do
      {:ok,
       %__MODULE__{
         aaguid: aaguid,
         authenticator_name: authenticator_name,
         credential_id: credential_id,
         credential_public_key: credential_public_key,
         raw: attested_credential_data,
         extensions: parse_extensions(extensions)
       }}
    else
      {:error, _} = error -> error
      _ -> @rounded_error
    end
  end

  defp format_aaguid(<<0::128>>), do: @unknown_aaguid

  defp format_aaguid(aaguid) do
    with <<
           part1::binary-size(8),
           part2::binary-size(4),
           part3::binary-size(4),
           part4::binary-size(4),
           part5::binary-size(12)
         >> <- Base.encode16(aaguid, case: :lower),
         aaguid_str <- Enum.join([part1, part2, part3, part4, part5], "-") do
      aaguid_str
    else
      _ -> @unknown_aaguid
    end
  end

  defp lookup_authenticator_name(@unknown_aaguid), do: nil

  defp lookup_authenticator_name(aaguid) do
    cond do
      # passkey
      Map.has_key?(@passkey_aaguid_list, aaguid) -> @passkey_aaguid_list[aaguid]["name"]
      # MDS
      Map.has_key?(@mds_aaguid_list, aaguid) -> @mds_aaguid_list[aaguid]["name"]
      true -> nil
    end
  end

  defp parse_extensions(""), do: nil

  defp parse_extensions(bytes) do
    case CBOR.decode(bytes) do
      {:ok, decoded, _} -> decoded
      _ -> nil
    end
  end
end
