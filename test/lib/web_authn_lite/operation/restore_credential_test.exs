defmodule WebAuthnLite.Operation.RestoreCredentialTest do
  use ExUnit.Case, async: false

  alias WebAuthnLite.StorablePublicKey
  alias WebAuthnLite.Operation.RestoreCredential

  # Keychain のテストデータを流用（BE=true, BS=true フラグ付き）
  # 実際の Android Restore Credentials のデータが取得でき次第、専用データに置き換える
  @encoded_attestation_object_keychain "o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YViYo3mm9u6vuaVeN4wRgDTidR5oL6ufLTCrE9ISVYbOGUddAAAAAAAAAAAAAAAAAAAAAAAAAAAAFCPmvJjrA9Cj6TU2H1Oa2r8fB9pGpQECAyYgASFYICdFZVoxrv4JsVRQRND88TV_Q917IgdcpF2jDg4cFelXIlgg5hQAmXqwfBISWno5v4dk1byQ0iUiq2P63yb1PfrFHmc"
  @encoded_authenticator_data_keychain "o3mm9u6vuaVeN4wRgDTidR5oL6ufLTCrE9ISVYbOGUcdAAAAAA"
  @encoded_client_data_json_keychain "eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoiS001UDA1M3o5SEtES25mREJDZEU2ZyIsIm9yaWdpbiI6Imh0dHBzOi8vZXhhbXBsZS5jb20iLCJjcm9zc09yaWdpbiI6ZmFsc2V9"
  @encoded_signature_keychain "MEQCIDWMoLHFQkcZLybJQ_PsFam6LNxVS7eWXNXsinqB3FkZAiAq1VCuISjiGkJznuxustoMoMBfh5n-XLSqHjxj0hTYVQ"
  @sample_rp_id "example.com"

  describe "validate_client_data_json" do
    # Android Restore Credentials の clientDataJSON（type: "webauthn.get"）
    @android_origin "android:apk-key-hash:sjYxqUM11Op8oHJuOdbrsCqtvYvbKHhQoKBlt28dLec"

    @webauthn_get_client_data_json Base.url_encode64(
                                     Jason.encode!(%{
                                       "type" => "webauthn.get",
                                       "challenge" => "test-challenge",
                                       "origin" => "android:apk-key-hash:sjYxqUM11Op8oHJuOdbrsCqtvYvbKHhQoKBlt28dLec",
                                       "androidPackageName" => "com.example.app"
                                     }),
                                     padding: false
                                   )

    @passkey_get_client_data_json Base.url_encode64(
                                    Jason.encode!(%{
                                      "type" => "passkey.get",
                                      "challenge" => "test-challenge",
                                      "origin" => "android:apk-key-hash:sjYxqUM11Op8oHJuOdbrsCqtvYvbKHhQoKBlt28dLec"
                                    }),
                                    padding: false
                                  )

    test "デフォルトの type（webauthn.get）と Android APK origin で検証成功" do
      assert {:ok, client_data_json} =
               RestoreCredential.validate_client_data_json(%{
                 client_data_json: @webauthn_get_client_data_json,
                 origin: @android_origin,
                 challenge: "test-challenge"
               })

      assert client_data_json.type == "webauthn.get"
    end

    test "type オプションで passkey.get を指定して検証成功" do
      assert {:ok, client_data_json} =
               RestoreCredential.validate_client_data_json(%{
                 client_data_json: @passkey_get_client_data_json,
                 origin: @android_origin,
                 challenge: "test-challenge",
                 type: "passkey.get"
               })

      assert client_data_json.type == "passkey.get"
    end

    test "type が一致しない場合はエラー" do
      assert {:error, :invalid_type} =
               RestoreCredential.validate_client_data_json(%{
                 client_data_json: @passkey_get_client_data_json,
                 origin: @android_origin,
                 challenge: "test-challenge"
               })
    end

    test "origin が一致しない場合はエラー" do
      assert {:error, :invalid_origin} =
               RestoreCredential.validate_client_data_json(%{
                 client_data_json: @webauthn_get_client_data_json,
                 origin: "android:apk-key-hash:wronghashvalue",
                 challenge: "test-challenge"
               })
    end

    test "challenge が一致しない場合はエラー" do
      assert {:error, :invalid_challenge} =
               RestoreCredential.validate_client_data_json(%{
                 client_data_json: @webauthn_get_client_data_json,
                 origin: @android_origin,
                 challenge: "wrong-challenge"
               })
    end
  end

  describe "validate_authenticator_assertion" do
    setup do
      {:ok, attestation_object} =
        WebAuthnLite.AttestationObject.decode(@encoded_attestation_object_keychain)

      storable_public_key = %StorablePublicKey{
        credential_id: attestation_object.auth_data.attested_credential_data.credential_id,
        public_key: attestation_object.auth_data.attested_credential_data.credential_public_key,
        sign_count: attestation_object.auth_data.sign_count
      }

      {:ok, storable_public_key: storable_public_key}
    end

    test "BE=true, BS=true のクレデンシャルで be_required/bs_required=true を検証成功",
         %{storable_public_key: storable_public_key} do
      assert {:ok, updated_storable_public_key, authenticator_data} =
               RestoreCredential.validate_authenticator_assertion(%{
                 credential_id: storable_public_key.credential_id,
                 signature: @encoded_signature_keychain,
                 authenticator_data: @encoded_authenticator_data_keychain,
                 client_data_json: @encoded_client_data_json_keychain,
                 public_keys: [storable_public_key],
                 rp_id: @sample_rp_id,
                 up_required: true,
                 uv_required: true,
                 be_required: true,
                 bs_required: true
               })

      assert authenticator_data.flags.be == true
      assert authenticator_data.flags.bs == true
      assert updated_storable_public_key.credential_id == storable_public_key.credential_id
    end

    test "be_required/bs_required を指定しない場合（デフォルト false）でも成功",
         %{storable_public_key: storable_public_key} do
      assert {:ok, _updated_storable_public_key, _authenticator_data} =
               RestoreCredential.validate_authenticator_assertion(%{
                 credential_id: storable_public_key.credential_id,
                 signature: @encoded_signature_keychain,
                 authenticator_data: @encoded_authenticator_data_keychain,
                 client_data_json: @encoded_client_data_json_keychain,
                 public_keys: [storable_public_key],
                 rp_id: @sample_rp_id,
                 up_required: true,
                 uv_required: true
               })
    end

    test "Chrome データ（BE=false, BS=false）で be_required=true はエラー" do
      # Chrome のデータは BE=false, BS=false のため、be_required=true でエラーになることを確認
      encoded_attestation_object_chrome =
        "o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YViko3mm9u6vuaVeN4wRgDTidR5oL6ufLTCrE9ISVYbOGUdFAAAAAK3OAAI1vMYKZIsLJfHwVQMAILv_1TM4JzTox-FHSHgOFEymS7zmPRK8YgtpTR_9GUUbpQECAyYgASFYIBE0VulC_XRULa4FpJ7MqvWPluXIOHWvwqq3N64Wu8lhIlggVpcik5uSvSvNTdlL2Okjjtu4bE-u1OAp8to2saFVa1M"

      encoded_authenticator_data_chrome = "o3mm9u6vuaVeN4wRgDTidR5oL6ufLTCrE9ISVYbOGUcFAAAAAA"

      encoded_client_data_json_chrome =
        "eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoiS001UDA1M3o5SEtES25mREJDZEU2ZyIsIm9yaWdpbiI6Imh0dHBzOi8vZXhhbXBsZS5jb20iLCJjcm9zc09yaWdpbiI6ZmFsc2V9"

      encoded_signature_chrome =
        "MEUCIDcWFNjAM_g10HjzzG3kD0Dzj28LIk4kWr9IkJST1SzCAiEAkrIctvKzDEh0wZ0WlN2ghLDgkIQp2p7bzT8czK0_lLo"

      {:ok, attestation_object} =
        WebAuthnLite.AttestationObject.decode(encoded_attestation_object_chrome)

      storable_public_key = %StorablePublicKey{
        credential_id: attestation_object.auth_data.attested_credential_data.credential_id,
        public_key: attestation_object.auth_data.attested_credential_data.credential_public_key,
        sign_count: attestation_object.auth_data.sign_count
      }

      assert {:error, :be_required} =
               RestoreCredential.validate_authenticator_assertion(%{
                 credential_id: storable_public_key.credential_id,
                 signature: encoded_signature_chrome,
                 authenticator_data: encoded_authenticator_data_chrome,
                 client_data_json: encoded_client_data_json_chrome,
                 public_keys: [storable_public_key],
                 rp_id: @sample_rp_id,
                 up_required: true,
                 uv_required: true,
                 be_required: true,
                 bs_required: false
               })
    end

    test "不正な署名はエラー", %{storable_public_key: storable_public_key} do
      assert {:error, :invalid_signature} =
               RestoreCredential.validate_authenticator_assertion(%{
                 credential_id: storable_public_key.credential_id,
                 signature: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                 authenticator_data: @encoded_authenticator_data_keychain,
                 client_data_json: @encoded_client_data_json_keychain,
                 public_keys: [storable_public_key],
                 rp_id: @sample_rp_id,
                 up_required: false,
                 uv_required: false
               })
    end

    test "不正な RP ID はエラー", %{storable_public_key: storable_public_key} do
      assert {:error, :invalid_rp_id_hash} =
               RestoreCredential.validate_authenticator_assertion(%{
                 credential_id: storable_public_key.credential_id,
                 signature: @encoded_signature_keychain,
                 authenticator_data: @encoded_authenticator_data_keychain,
                 client_data_json: @encoded_client_data_json_keychain,
                 public_keys: [storable_public_key],
                 rp_id: "wrong.example.com",
                 up_required: false,
                 uv_required: false
               })
    end
  end
end
