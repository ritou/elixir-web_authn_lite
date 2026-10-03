defmodule WebAuthnLite.Operation.RestoreCredential do
  @moduledoc """
  Android Restore Credentials のアサーションを検証する関数群

  Android の Credential Manager API で GetRestoreCredentialOption を使用して
  取得したクレデンシャルをサーバー側で検証するためのモジュール。

  ## 通常の WebAuthn 認証 (Operation.Authenticate) との主な違い

  - **UP (User Presence) フラグ** — バックグラウンドで実行されるため `false` になりうる
  - **origin 形式** — ブラウザの `https://...` ではなく、APK 署名証明書ハッシュを使用
    - 形式: `android:apk-key-hash:<Base64URL(SHA-256(signing_cert))>`
    - リリース用とデバッグ用の両ハッシュを許容する設計を推奨
  - **BE (Backup Eligible) フラグ** — Restore Credentials では常に `true` になるため、
    `be_required: true` を指定することでバックアップ対象クレデンシャルを識別可能
  - **clientDataJSON の type** — 現時点では `"webauthn.get"` が使用されると見られるが、
    Android の実装によって異なる可能性がある。`type` オプションで上書き可能
  - **AAGUID** — 全ゼロ (`00000000-0000-0000-0000-000000000000`) になる

  ## DB 管理上の注意点

  Restore Credentials はプロトコルレベルでは通常パスキーと区別できないため、
  DB 側でクレデンシャルの種別（restore_key / passkey）を管理することを推奨する。
  Restore Credentials はユーザー向けのパスキー管理 UI に表示しないよう注意。

  https://developer.android.com/distribute/aep/aep-req-restore-credentials
  https://developer.android.com/identity/sign-in/restore-credentials-implementation
  """

  alias WebAuthnLite.{ClientDataJSON, AuthenticatorData, Signature, StorablePublicKey}

  @restore_credential_type "webauthn.get"

  @rounded_error_client_data_json {:error, :invalid_client_data_json}
  @rounded_error_authenticator_assertion {:error, :invalid_authenticator_assertion}

  @doc """
  clientDataJSON を検証して構造体を返す。

  ```
  {:ok, client_data_json} =
    WebAuthnLite.Operation.RestoreCredential.validate_client_data_json(%{
      client_data_json: encoded_client_data_json,
      origin: "android:apk-key-hash:<Base64URL(SHA-256(signing_cert))>",
      challenge: challenge
    })
  ```

  `type` を指定しない場合は #{inspect(@restore_credential_type)} を使用する。
  実際の Android デバイスから送られる type 値を確認した上で、
  必要であれば `type` オプションで上書きすること。

  `origin` には Android アプリの APK 署名ハッシュを指定する:
  `android:apk-key-hash:<Base64URL(SHA-256(signing_cert))>`
  リリース用とデバッグ用の証明書が異なるため、複数の origin を
  上位のアプリケーション層で管理することを推奨する。
  """
  @spec validate_client_data_json(params :: map) ::
          {:ok, client_data_json :: ClientDataJSON.t()} | {:error, term}
  def validate_client_data_json(%{
        client_data_json: encoded_client_data_json,
        origin: origin,
        challenge: challenge
      } = params) do
    type = Map.get(params, :type, @restore_credential_type)

    case ClientDataJSON.validate(
           encoded_client_data_json,
           type,
           origin,
           challenge
         ) do
      {:ok, _client_data_json} = valid -> valid
      {:error, _} = invalid -> invalid
      _ -> @rounded_error_client_data_json
    end
  end

  @doc """
  Restore Credential のアサーションを検証して構造体を返す。

  通常の認証と異なり、デバイス移行時は UP (User Presence) フラグが
  false になることがあるため、用途に応じて `up_required` を設定する。

  Restore Credentials では authenticatorData の BE (Backup Eligible) と
  BS (Backup State) フラグも検証できる。
  - `be_required: true` — クレデンシャルがバックアップ対象であることを要求する
  - `bs_required: true` — クレデンシャルが実際にバックアップ済みであることを要求する

  ```
  {:ok, storable_public_key, authenticator_data} =
    WebAuthnLite.Operation.RestoreCredential.validate_authenticator_assertion(%{
      credential_id: credential_id,
      signature: encoded_signature,
      authenticator_data: encoded_authenticator_data,
      client_data_json: encoded_client_data_json,
      public_keys: [storable_public_key],
      rp_id: rp_id,
      up_required: false,
      uv_required: false,
      be_required: true,
      bs_required: true
    })
  ```
  """
  @spec validate_authenticator_assertion(params :: map) ::
          {:ok, updated_storable_public_key :: StorablePublicKey.t(),
           authenticator_data :: WebAuthnLite.AuthenticatorData.t()}
          | {:error, term}
  def validate_authenticator_assertion(%{
        credential_id: credential_id,
        signature: encoded_signature,
        authenticator_data: encoded_authenticator_data,
        client_data_json: encoded_client_data_json,
        public_keys: public_keys,
        rp_id: rp_id,
        up_required: up_required,
        uv_required: uv_required
      } = params) do
    be_required = Map.get(params, :be_required, false)
    bs_required = Map.get(params, :bs_required, false)

    with {:ok, authenticator_data} <- AuthenticatorData.decode(encoded_authenticator_data),
         {:ok, client_data_json} <- ClientDataJSON.decode(encoded_client_data_json),
         public_key when not is_nil(public_key) <- lookup_public_key(public_keys, credential_id) do
      cond do
        !Signature.valid?(
          encoded_signature,
          authenticator_data,
          client_data_json,
          public_key.public_key
        ) ->
          {:error, :invalid_signature}

        !AuthenticatorData.valid_rp_id_hash?(rp_id, authenticator_data.rp_id_hash) ->
          {:error, :invalid_rp_id_hash}

        up_required && !authenticator_data.flags.up ->
          {:error, :up_required}

        uv_required && !authenticator_data.flags.uv ->
          {:error, :uv_required}

        be_required && !authenticator_data.flags.be ->
          {:error, :be_required}

        bs_required && !authenticator_data.flags.bs ->
          {:error, :bs_required}

        public_key.sign_count > 0 && authenticator_data.sign_count > 0 &&
            public_key.sign_count >= authenticator_data.sign_count ->
          {:error, :invalid_sign_count}

        true ->
          {:ok,
           %StorablePublicKey{
             credential_id: public_key.credential_id,
             public_key: public_key.public_key,
             sign_count: authenticator_data.sign_count
           }, authenticator_data}
      end
    else
      {:error, _} = invalid -> invalid
      _ -> @rounded_error_authenticator_assertion
    end
  end

  defp lookup_public_key(public_keys, credential_id) do
    Enum.find(public_keys, fn public_key -> public_key.credential_id == credential_id end)
  end
end
