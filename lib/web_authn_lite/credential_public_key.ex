defmodule WebAuthnLite.CredentialPublicKey do
  @cbor_map_key_alg 3
  @cbor_map_key_alg_rs256 -257

  def decode(cbor_map) do
    case cbor_map[@cbor_map_key_alg] do
      @cbor_map_key_alg_rs256 ->
        cbor_map |> WebAuthnLite.CredentialPublicKey.RSA.from_cbor_map()

      _ ->
        nil
    end
  end
end
