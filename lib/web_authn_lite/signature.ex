defmodule WebAuthnLite.Signature do
  @moduledoc """
  Functions for signature verification
  """

  require Logger

  @doc """
  verify base64 URL encoded signature.

  NOTE: This function has not been implemented yet.
  """
  @spec valid?(
          base64_url_encoded_signature :: String.t(),
          authenticator_data :: WebAuthnLite.AuthenticatorData.t(),
          client_data_json :: WebAuthnLite.ClientDataJSON.t(),
          public_key :: WebAuthnLite.PublicKey.t()
        ) :: boolean
  def valid?(_base64_url_encoded_signature, _authenticator_data, _client_data_json, _public_key) do
    # signature = base64_url_encoded_signature |> Base.url_decode64!(padding: false),
    # signature_base_binary = authenticator_data.raw <> client_data_json.hash
    Logger.warn("SORRY. This function has not been implemented yet.")
    false
  end
end
