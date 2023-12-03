defmodule WebAuthnLite.Operation.AuthenticateTest do
  use ExUnit.Case, async: false

  alias WebAuthnLite.StorablePublicKey
  alias WebAuthnLite.Operation.Authenticate
  # doctest Authenticate

  # for basic test
  @encoded_attestation_object "o2NmbXRmcGFja2VkZ2F0dFN0bXSjY2FsZyZjc2lnWEcwRQIgA_2zNZ2yCRDELCX545G4y5ZG7R2LSuz11pw_fgueVggCIQDEY3H5X93IE-pmNvJFCrwOUx6_ljzjBq3jwEYsH-_khWN4NWOBWQLCMIICvjCCAaagAwIBAgIEdIb9wjANBgkqhkiG9w0BAQsFADAuMSwwKgYDVQQDEyNZdWJpY28gVTJGIFJvb3QgQ0EgU2VyaWFsIDQ1NzIwMDYzMTAgFw0xNDA4MDEwMDAwMDBaGA8yMDUwMDkwNDAwMDAwMFowbzELMAkGA1UEBhMCU0UxEjAQBgNVBAoMCVl1YmljbyBBQjEiMCAGA1UECwwZQXV0aGVudGljYXRvciBBdHRlc3RhdGlvbjEoMCYGA1UEAwwfWXViaWNvIFUyRiBFRSBTZXJpYWwgMTk1NTAwMzg0MjBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABJVd8633JH0xde_9nMTzGk6HjrrhgQlWYVD7OIsuX2Unv1dAmqWBpQ0KxS8YRFwKE1SKE1PIpOWacE5SO8BN6-2jbDBqMCIGCSsGAQQBgsQKAgQVMS4zLjYuMS40LjEuNDE0ODIuMS4xMBMGCysGAQQBguUcAgEBBAQDAgUgMCEGCysGAQQBguUcAQEEBBIEEPigEfOMCk0VgAYXER-e3H0wDAYDVR0TAQH_BAIwADANBgkqhkiG9w0BAQsFAAOCAQEAMVxIgOaaUn44Zom9af0KqG9J655OhUVBVW-q0As6AIod3AH5bHb2aDYakeIyyBCnnGMHTJtuekbrHbXYXERIn4aKdkPSKlyGLsA_A-WEi-OAfXrNVfjhrh7iE6xzq0sg4_vVJoywe4eAJx0fS-Dl3axzTTpYl71Nc7p_NX6iCMmdik0pAuYJegBcTckE3AoYEg4K99AM_JaaKIblsbFh8-3LxnemeNf7UwOczaGGvjS6UzGVI0Odf9lKcPIwYhuTxM5CaNMXTZQ7xq4_yTfC3kPWtE4hFT34UJJflZBiLrxG4OsYxkHw_n5vKgmpspB3GfYuYTWhkDKiE8CYtyg87mhhdXRoRGF0YViUSZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2NBAAAAC_igEfOMCk0VgAYXER-e3H0AEDIBRoyihvjNZOR2yfjLPhulAQIDJiABIVggIXUM4qBXox--h7XwLrTlN4oPj-8bE27wjXlEZIRHL4kiWCBFllqpZSGGRUTgbLTjR5_H4oUr0SJIm3oE659m5sVxUw"
  @encoded_authenticator_data "SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MBAAAADA"
  @encoded_client_data_json "eyJjaGFsbGVuZ2UiOiJJOV9idk5DRzNNell6Zkc2V0NPNGNhVVUwcnJjbEVNVTJETElnWmVNR3R3Iiwib3JpZ2luIjoiaHR0cDovL2xvY2FsaG9zdDo0MDAwIiwidHlwZSI6IndlYmF1dGhuLmdldCJ9"
  @encoded_signature "MEQCIH22OhUJTVAdjFoNuxcjC4Vz0Ju4N1r378sA6v-DnMugAiAYoWx2s3j6C37Vgfz04Dq_lV9ybFL3JHySPLEXJGrRhw"
  @origin "http://localhost:4000"
  @challenge "I9_bvNCG3MzYzfG6WCO4caUU0rrclEMU2DLIgZeMGtw"
  @rp_id "localhost"
  @credential_id "MgFGjKKG-M1k5HbJ-Ms-Gw"

  # for actual authenticator's log
  @sample_rp_id "example.com"

  # keychain
  @encoded_attestation_object_keychain "o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YViYo3mm9u6vuaVeN4wRgDTidR5oL6ufLTCrE9ISVYbOGUddAAAAAAAAAAAAAAAAAAAAAAAAAAAAFCPmvJjrA9Cj6TU2H1Oa2r8fB9pGpQECAyYgASFYICdFZVoxrv4JsVRQRND88TV_Q917IgdcpF2jDg4cFelXIlgg5hQAmXqwfBISWno5v4dk1byQ0iUiq2P63yb1PfrFHmc"
  @encoded_authenticator_data_keychain "o3mm9u6vuaVeN4wRgDTidR5oL6ufLTCrE9ISVYbOGUcdAAAAAA"
  @encoded_client_data_json_keychain "eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoiS001UDA1M3o5SEtES25mREJDZEU2ZyIsIm9yaWdpbiI6Imh0dHBzOi8vZXhhbXBsZS5jb20iLCJjcm9zc09yaWdpbiI6ZmFsc2V9"
  @encoded_signature_keychain "MEQCIDWMoLHFQkcZLybJQ_PsFam6LNxVS7eWXNXsinqB3FkZAiAq1VCuISjiGkJznuxustoMoMBfh5n-XLSqHjxj0hTYVQ"

  # Chrome on MacOS
  @encoded_attestation_object_chrome "o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YViko3mm9u6vuaVeN4wRgDTidR5oL6ufLTCrE9ISVYbOGUdFAAAAAK3OAAI1vMYKZIsLJfHwVQMAILv_1TM4JzTox-FHSHgOFEymS7zmPRK8YgtpTR_9GUUbpQECAyYgASFYIBE0VulC_XRULa4FpJ7MqvWPluXIOHWvwqq3N64Wu8lhIlggVpcik5uSvSvNTdlL2Okjjtu4bE-u1OAp8to2saFVa1M"
  @encoded_authenticator_data_chrome "o3mm9u6vuaVeN4wRgDTidR5oL6ufLTCrE9ISVYbOGUcFAAAAAA"
  @encoded_client_data_json_chrome "eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoiS001UDA1M3o5SEtES25mREJDZEU2ZyIsIm9yaWdpbiI6Imh0dHBzOi8vZXhhbXBsZS5jb20iLCJjcm9zc09yaWdpbiI6ZmFsc2V9"
  @encoded_signature_chrome "MEUCIDcWFNjAM_g10HjzzG3kD0Dzj28LIk4kWr9IkJST1SzCAiEAkrIctvKzDEh0wZ0WlN2ghLDgkIQp2p7bzT8czK0_lLo"

  describe "basic" do
    test "validate_client_data_json" do
      assert {:ok, _client_data_json} =
               Authenticate.validate_client_data_json(%{
                 client_data_json: @encoded_client_data_json,
                 origin: @origin,
                 challenge: @challenge
               })
    end

    test "validate_authenticator_assertion" do
      {:ok, attestation_object} =
        WebAuthnLite.AttestationObject.decode(@encoded_attestation_object)

      storable_public_key = %StorablePublicKey{
        credential_id: attestation_object.auth_data.attested_credential_data.credential_id,
        public_key: attestation_object.auth_data.attested_credential_data.credential_public_key,
        sign_count: attestation_object.auth_data.sign_count
      }

      assert {:ok, updated_storable_public_key, _authenticator_data} =
               Authenticate.validate_authenticator_assertion(%{
                 credential_id: @credential_id,
                 signature: @encoded_signature,
                 authenticator_data: @encoded_authenticator_data,
                 client_data_json: @encoded_client_data_json,
                 public_keys: [storable_public_key],
                 rp_id: @rp_id,
                 up_required: true,
                 uv_required: false
               })

      assert updated_storable_public_key.sign_count > storable_public_key.sign_count
    end
  end

  describe "actual authenticator's log" do
    test "keychain" do
      {:ok, attestation_object} =
        WebAuthnLite.AttestationObject.decode(@encoded_attestation_object_keychain)

      storable_public_key = %StorablePublicKey{
        credential_id: attestation_object.auth_data.attested_credential_data.credential_id,
        public_key: attestation_object.auth_data.attested_credential_data.credential_public_key,
        sign_count: attestation_object.auth_data.sign_count
      }

      assert {:ok, updated_storable_public_key, authenticator_data} =
               Authenticate.validate_authenticator_assertion(%{
                 credential_id: storable_public_key.credential_id,
                 signature: @encoded_signature_keychain,
                 authenticator_data: @encoded_authenticator_data_keychain,
                 client_data_json: @encoded_client_data_json_keychain,
                 public_keys: [storable_public_key],
                 rp_id: @sample_rp_id,
                 up_required: true,
                 uv_required: true
               })

      assert %WebAuthnLite.StorablePublicKey{
               credential_id: "I-a8mOsD0KPpNTYfU5ravx8H2kY",
               public_key: %WebAuthnLite.CredentialPublicKey.ES256{
                 key: {{:ECPoint, _}, {:namedCurve, {1, 2, 840, 10045, 3, 1, 7}}},
                 digest_type: :sha256,
                 map: %{
                   "crv" => "P-256",
                   "kty" => "EC",
                   "x" => "J0VlWjGu_gmxVFBE0PzxNX9D3XsiB1ykXaMODhwV6Vc",
                   "y" => "5hQAmXqwfBISWno5v4dk1byQ0iUiq2P63yb1PfrFHmc"
                 },
                 json:
                   "{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"J0VlWjGu_gmxVFBE0PzxNX9D3XsiB1ykXaMODhwV6Vc\",\"y\":\"5hQAmXqwfBISWno5v4dk1byQ0iUiq2P63yb1PfrFHmc\"}"
               },
               sign_count: 0
             } = updated_storable_public_key

      assert %WebAuthnLite.AuthenticatorData{
               rp_id_hash: "o3mm9u6vuaVeN4wRgDTidR5oL6ufLTCrE9ISVYbOGUc",
               flags: %WebAuthnLite.AuthenticatorData.Flags{
                 flags: <<29>>,
                 up: true,
                 uv: true,
                 be: true,
                 bs: true,
                 at: false,
                 ed: false
               },
               sign_count: 0,
               raw:
                 <<163, 121, 166, 246, 238, 175, 185, 165, 94, 55, 140, 17, 128, 52, 226, 117, 30,
                   104, 47, 171, 159, 45, 48, 171, 19, 210, 18, 85, 134, 206, 25, 71, 29, 0, 0, 0,
                   0>>,
               attested_credential_data: nil,
               extensions: nil
             } = authenticator_data
    end

    test "chrome" do
      {:ok, attestation_object} =
        WebAuthnLite.AttestationObject.decode(@encoded_attestation_object_chrome)

      storable_public_key = %StorablePublicKey{
        credential_id: attestation_object.auth_data.attested_credential_data.credential_id,
        public_key: attestation_object.auth_data.attested_credential_data.credential_public_key,
        sign_count: attestation_object.auth_data.sign_count
      }

      assert {:ok, updated_storable_public_key, authenticator_data} =
               Authenticate.validate_authenticator_assertion(%{
                 credential_id: storable_public_key.credential_id,
                 signature: @encoded_signature_chrome,
                 authenticator_data: @encoded_authenticator_data_chrome,
                 client_data_json: @encoded_client_data_json_chrome,
                 public_keys: [storable_public_key],
                 rp_id: @sample_rp_id,
                 up_required: true,
                 uv_required: true
               })

      assert %WebAuthnLite.StorablePublicKey{
               credential_id: "u__VMzgnNOjH4UdIeA4UTKZLvOY9ErxiC2lNH_0ZRRs",
               public_key: %WebAuthnLite.CredentialPublicKey.ES256{
                 key: {{:ECPoint, _}, {:namedCurve, {1, 2, 840, 10045, 3, 1, 7}}},
                 digest_type: :sha256,
                 map: %{
                   "crv" => "P-256",
                   "kty" => "EC",
                   "x" => "ETRW6UL9dFQtrgWknsyq9Y-W5cg4da_Cqrc3rha7yWE",
                   "y" => "Vpcik5uSvSvNTdlL2Okjjtu4bE-u1OAp8to2saFVa1M"
                 },
                 json:
                   "{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"ETRW6UL9dFQtrgWknsyq9Y-W5cg4da_Cqrc3rha7yWE\",\"y\":\"Vpcik5uSvSvNTdlL2Okjjtu4bE-u1OAp8to2saFVa1M\"}"
               },
               sign_count: 0
             } = updated_storable_public_key

      assert %WebAuthnLite.AuthenticatorData{
               rp_id_hash: "o3mm9u6vuaVeN4wRgDTidR5oL6ufLTCrE9ISVYbOGUc",
               flags: %WebAuthnLite.AuthenticatorData.Flags{
                 flags: <<5>>,
                 up: true,
                 uv: true,
                 be: false,
                 bs: false,
                 at: false,
                 ed: false
               },
               sign_count: 0,
               raw: _,
               attested_credential_data: nil,
               extensions: nil
             } = authenticator_data
    end
  end
end
