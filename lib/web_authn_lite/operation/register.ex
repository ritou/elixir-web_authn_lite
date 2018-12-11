defmodule WebAuthnLite.Operation.Register do
  @moduledoc """
  Functions for Registering a new credential operation

  https://www.w3.org/TR/webauthn/#registering-a-new-credential
  """

  alias WebAuthnLite.{ClientDataJSON, AttestationObject, AuthenticatorData, StorablePublicKey}

  @registration_type "webauthn.create"

  @rounded_error_client_data_json {:error, :invalid_client_data_json}
  @rounded_error_attestation_object {:error, :invalid_attestation_object}

  @doc """
  Verify clientDataJSON and return struct.

  ```
  {:ok, client_data_json} =
    WebAuthnLite.Operation.Register.validate_client_data_json(%{
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
    case ClientDataJSON.validate(encoded_client_data_json, @registration_type, origin, challenge) do
      {:ok, _client_data_json} = valid -> valid
      {:error, _} = invalid -> invalid
      _ -> @rounded_error_client_data_json
    end
  end

  @doc """
  Verify attestation object and return public key.

  # NOTE: This function doesn't verify attestation statement yet.

  ```
  {:ok, storable_public_key} =
    WebAuthnLite.Operation.Register.validate_attestation_object(%{
      attestation_object: encoded_attestation_object,
      client_data_json: encoded_client_data_json,
      rp_id: rp_id,
      up_required: true,
      uv_required: false,
    })
  ```
  """
  @spec validate_attestation_object(params :: map) ::
          {:ok, storable_public_key :: StorablePublicKey.t(),
           attestation_object :: AttestationObject.t()}
          | {:error, term}
  def validate_attestation_object(%{
        attestation_object: encoded_attestation_object,
        # for validate attestation
        client_data_json: _client_data_json,
        rp_id: rp_id,
        up_required: up_required,
        uv_required: uv_required
      }) do
    case AttestationObject.decode(encoded_attestation_object) do
      {:ok, attestation_object} ->
        cond do
          !AuthenticatorData.valid_rp_id_hash?(rp_id, attestation_object.auth_data.rp_id_hash) ->
            {:error, :invalid_rp_id_hash}

          up_required && !attestation_object.auth_data.flags.up ->
            {:error, :up_required}

          uv_required && !attestation_object.auth_data.flags.uv ->
            {:error, :uv_required}

          true ->
            {:ok,
             %StorablePublicKey{
               credential_id: attestation_object.auth_data.attested_credential_data.credential_id,
               public_key:
                 attestation_object.auth_data.attested_credential_data.credential_public_key,
               sign_count: attestation_object.auth_data.sign_count
             }, attestation_object}
        end

      {:error, _} = invalid ->
        invalid

      _ ->
        @rounded_error_attestation_object
    end
  end
end
