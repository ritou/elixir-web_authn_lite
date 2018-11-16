defmodule WebAuthnLite.CredentialPublicKey.ES256 do
  defstruct [:key, :digest_type]

  @type t :: %__MODULE__{
          key: term,
          digest_type: atom
        }

  @spec from_cbor_map(map) :: t
  def from_cbor_map(cbor_map) do
    with key_map <- %{
           "kty" => "EC",
           "crv" => "P-256",
           "x" => cbor_map[-2] |> Base.encode64(),
           "y" => cbor_map[-3] |> Base.encode64()
         },
         {:jose_jwk_kty_ec, key} <- JOSE.JWK.from_map(key_map).kty do
      %__MODULE__{digest_type: :sha256, key: key}
    else
      _ -> {:error, :invalid_key}
    end
  end
end
