defmodule WebAuthnLite.Signature do
  @moduledoc """
  Functions for signature verification
  """

  require Logger

  @doc """
  verify base64 URL encoded signature.
  """
  @spec valid?(
          base64_url_encoded_signature :: String.t(),
          authenticator_data :: WebAuthnLite.AuthenticatorData.t(),
          client_data_json :: WebAuthnLite.ClientDataJSON.t(),
          public_key :: WebAuthnLite.PublicKey.t()
        ) :: boolean
  def valid?(base64_url_encoded_signature, authenticator_data, client_data_json, public_key) do
    signature = base64_url_encoded_signature |> Base.url_decode64!(padding: false)
    signature_base_binary = authenticator_data.raw <> client_data_json.hash
    :public_key.verify(signature_base_binary, public_key.digest_type, signature, public_key.key)
  end
end
