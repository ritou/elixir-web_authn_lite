defmodule WebAuthnLite.CredentialPublicKey do
  @moduledoc """
  Functions for handling CredentialPublicKey

  https://www.w3.org/TR/webauthn/#credential-public-key
  """

  @cbor_map_key_alg 3
  @cbor_map_key_alg_rs256 -257
  @cbor_map_key_alg_es256 -7
  # TODO: support other algs

  @spec from_cbor_map(cbor_map :: map) :: WebAuthnLite.CredentialPublicKey.RS256.t | WebAuthnLite.CredentialPublicKey.ES256.t
  def from_cbor_map(cbor_map) do
    case cbor_map[@cbor_map_key_alg] do
      @cbor_map_key_alg_rs256 ->
        cbor_map |> WebAuthnLite.CredentialPublicKey.RS256.from_cbor_map()

      @cbor_map_key_alg_es256 ->
        cbor_map |> WebAuthnLite.CredentialPublicKey.ES256.from_cbor_map()

      _ ->
        nil
    end
  end
end
