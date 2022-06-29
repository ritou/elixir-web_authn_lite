defmodule WebAuthnLite.CredentialPublicKey.ES256 do
  defstruct [:key, :digest_type, :map, :json]

  @type t :: %__MODULE__{
          key: term,
          digest_type: atom,
          map: map,
          json: String.t()
        }

  @jose_jwk_kty :jose_jwk_kty_ec

  @spec from_cbor_map(map) :: t
  def from_cbor_map(cbor_map) do
    with key_map <- %{
           "kty" => "EC",
           "crv" => "P-256",
           "x" => cbor_map[-2] |> Base.url_encode64(padding: false),
           "y" => cbor_map[-3] |> Base.url_encode64(padding: false)
         },
         {@jose_jwk_kty, key} <- JOSE.JWK.from_map(key_map).kty do
      %__MODULE__{digest_type: :sha256, key: key, map: key_map, json: key_map |> Jason.encode!()}
    else
      _ -> {:error, :invalid_key}
    end
  end

  @spec from_jwk(jwk :: JOSE.JWK.t()) :: t
  def from_jwk(jwk) do
    with {@jose_jwk_kty, key} <- jwk.kty,
         {%{kty: @jose_jwk_kty}, key_map} = JOSE.JWK.to_map(jwk) do
      %__MODULE__{digest_type: :sha256, key: key, map: key_map, json: key_map |> Jason.encode!()}
    else
      _ -> {:error, :invalid_key}
    end
  end
end
