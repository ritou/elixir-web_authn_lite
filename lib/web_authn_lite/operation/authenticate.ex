defmodule WebAuthnLite.Operation.Authenticate do
  @moduledoc """
  Functions for Verifying an authentication assertion operation

  https://www.w3.org/TR/webauthn/#verifying-assertion
  """

  alias WebAuthnLite.{ClientDataJSON, AuthenticatorData, Signature}

  @authentication_type "webauthn.get"

  @rounded_error_client_data_json {:error, :invalid_client_data_json}
  @rounded_error_authenticator_assertion {:error, :invalid_authenticator_assertion}

  @doc """
  Verify clientDataJSON and return struct.

  ```
  {:ok, client_data_json} =
    WebAuthnLite.Operation.Authenticate.validate_client_data_json(%{
      client_data_json: encoded_client_data_json,
      origin: origin,
      challenge: challenge
    })
  ```
  """
  @spec validate_client_data_json(params :: map) ::
          {:ok, client_data_json :: ClientDataJSON.t()} | {:error, term}
  def validate_client_data_json(%{
        client_data_json: encoded_client_data_json,
        origin: origin,
        challenge: challenge
      }) do
    case ClientDataJSON.validate(
           encoded_client_data_json,
           @authentication_type,
           origin,
           challenge
         ) do
      {:ok, _client_data_json} = valid -> valid
      {:error, _} = invalid -> invalid
      _ -> @rounded_error_client_data_json
    end
  end

  @doc """
  Verify AuthenticatorResponse and return struct.

  ```
  {:ok, authenticator_data} =
    WebAuthnLite.Operation.Authenticate.validate_authenticator_assertion(%{
      signature: encoded_signature,
      authenticator_data: encoded_authenticator_data,
      client_data_json: encoded_client_data_json,
      public_key: public_key,
      rp_id: rp_id,
      up_required: true,
      uv_required: false,
      sign_count: sign_count
    })
  ```
  """
  @spec validate_authenticator_assertion(params :: map) ::
          {:ok, authenticator_data :: WebAuthnLite.AuthenticatorData.t()} | {:error, term}
  def validate_authenticator_assertion(%{
        signature: encoded_signature,
        authenticator_data: encoded_authenticator_data,
        client_data_json: encoded_client_data_json,
        public_key: public_key,
        rp_id: rp_id,
        up_required: up_required,
        uv_required: uv_required,
        sign_count: sign_count
      }) do
    with {:ok, authenticator_data} <- AuthenticatorData.decode(encoded_authenticator_data),
         {:ok, client_data_json} <- ClientDataJSON.decode(encoded_client_data_json) do
      cond do
        !Signature.valid?(encoded_signature, authenticator_data, client_data_json, public_key) ->
          {:error, :invalid_signature}

        !AuthenticatorData.valid_rp_id_hash?(rp_id, authenticator_data.rp_id_hash) ->
          {:error, :invalid_rp_id_hash}

        up_required && !authenticator_data.flags.up ->
          {:error, :up_required}

        uv_required && !authenticator_data.flags.uv ->
          {:error, :uv_required}

        sign_count >= authenticator_data.sign_count ->
          {:error, :invalid_sign_count}

        true ->
          {:ok, authenticator_data}
      end
    else
      {:error, _} = invalid -> invalid
      _ -> @rounded_error_authenticator_assertion
    end
  end
end
