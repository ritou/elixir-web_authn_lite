defmodule WebAuthnLite.CredentialPublicKey do
  @moduledoc """
  Functions for handling CredentialPublicKey

  https://www.w3.org/TR/webauthn/#credential-public-key
  """

  @cbor_map_key_alg 3
  @cbor_map_key_alg_rs256 -257
  @cbor_map_key_alg_es256 -7
  # TODO: support other algs

  @spec from_cbor_map(cbor_map :: map) ::
          WebAuthnLite.CredentialPublicKey.RS256.t()
          | WebAuthnLite.CredentialPublicKey.ES256.t()
          | {:error, :invalid_credential_public_key}
  def from_cbor_map(cbor_map) do
    case cbor_map[@cbor_map_key_alg] do
      @cbor_map_key_alg_rs256 ->
        cbor_map |> WebAuthnLite.CredentialPublicKey.RS256.from_cbor_map()

      @cbor_map_key_alg_es256 ->
        cbor_map |> WebAuthnLite.CredentialPublicKey.ES256.from_cbor_map()

      _ ->
        {:error, :invalid_credential_public_key}
    end
  end

  @spec from_json(json_encoded_key_map :: String.t()) ::
          WebAuthnLite.CredentialPublicKey.RS256.t()
          | WebAuthnLite.CredentialPublicKey.ES256.t()
          | {:error, :invalid_credential_public_key}
  def from_json(json_encoded_key_map) do
    try do
      with key_map <- json_encoded_key_map |> Jason.decode!() do
        key_map |> from_key_map()
      end
    rescue
      _ -> {:error, :invalid_credential_public_key}
    end
  end

  @spec from_key_map(key_map :: map) ::
          WebAuthnLite.CredentialPublicKey.RS256.t()
          | WebAuthnLite.CredentialPublicKey.ES256.t()
          | {:error, :invalid_credential_public_key}
  def from_key_map(key_map) do
    try do
      # Convert to Base64URL Encode format for compatibility with encoding issues in past versions
      jwk = key_map |> convert_key_map_to_base64url_encoding() |> JOSE.JWK.from_map()

      case jwk.kty |> elem(0) do
        :jose_jwk_kty_rsa -> jwk |> WebAuthnLite.CredentialPublicKey.RS256.from_jwk()
        :jose_jwk_kty_ec -> jwk |> WebAuthnLite.CredentialPublicKey.ES256.from_jwk()
        _ -> {:error, :invalid_credential_public_key}
      end
    rescue
      _ -> {:error, :invalid_credential_public_key}
    catch
      _ -> {:error, :invalid_credential_public_key}
    end
  end

  defp convert_key_map_to_base64url_encoding(key_map) do
    for {k, v} <- key_map,
        into: %{},
        do: {k, v |> String.replace("+", "-") |> String.replace("/", "_")}
  end
end
