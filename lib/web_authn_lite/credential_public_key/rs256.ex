defmodule WebAuthnLite.CredentialPublicKey.RSA do
  defstruct [:jose_jwk]

  @type t :: %__MODULE__{
          jose_jwk: JOSE.JWK.t()
        }

  def from_cbor_map(cbor_map) do
    with key_map <- %{
           "kty" => "RSA",
           "n" => cbor_map[-1] |> Base.encode64(),
           "e" => cbor_map[-2] |> Base.encode64()
         },
         jose_jwk = %JOSE.JWK{} <- JOSE.JWK.from_map(key_map) do
      %__MODULE__{jose_jwk: jose_jwk}
    else
      _ -> {:error, :invalid_key}
    end
  end

  @spec to_pem(cred_pubkey_rsa :: t) :: String.t()
  def to_pem(cred_pubkey_rsa) do
    cred_pubkey_rsa.jose_jwk |> JOSE.JWK.to_pem()
  end
end
