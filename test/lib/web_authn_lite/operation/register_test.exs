defmodule WebAuthnLite.Operation.RegisterTest do
  use ExUnit.Case, async: false

  alias WebAuthnLite.StorablePublicKey
  alias WebAuthnLite.Operation.Register
  # doctest Register

  # for basic test
  @encoded_attestation_object "o2NmbXRmcGFja2VkZ2F0dFN0bXSjY2FsZyZjc2lnWEcwRQIgA_2zNZ2yCRDELCX545G4y5ZG7R2LSuz11pw_fgueVggCIQDEY3H5X93IE-pmNvJFCrwOUx6_ljzjBq3jwEYsH-_khWN4NWOBWQLCMIICvjCCAaagAwIBAgIEdIb9wjANBgkqhkiG9w0BAQsFADAuMSwwKgYDVQQDEyNZdWJpY28gVTJGIFJvb3QgQ0EgU2VyaWFsIDQ1NzIwMDYzMTAgFw0xNDA4MDEwMDAwMDBaGA8yMDUwMDkwNDAwMDAwMFowbzELMAkGA1UEBhMCU0UxEjAQBgNVBAoMCVl1YmljbyBBQjEiMCAGA1UECwwZQXV0aGVudGljYXRvciBBdHRlc3RhdGlvbjEoMCYGA1UEAwwfWXViaWNvIFUyRiBFRSBTZXJpYWwgMTk1NTAwMzg0MjBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABJVd8633JH0xde_9nMTzGk6HjrrhgQlWYVD7OIsuX2Unv1dAmqWBpQ0KxS8YRFwKE1SKE1PIpOWacE5SO8BN6-2jbDBqMCIGCSsGAQQBgsQKAgQVMS4zLjYuMS40LjEuNDE0ODIuMS4xMBMGCysGAQQBguUcAgEBBAQDAgUgMCEGCysGAQQBguUcAQEEBBIEEPigEfOMCk0VgAYXER-e3H0wDAYDVR0TAQH_BAIwADANBgkqhkiG9w0BAQsFAAOCAQEAMVxIgOaaUn44Zom9af0KqG9J655OhUVBVW-q0As6AIod3AH5bHb2aDYakeIyyBCnnGMHTJtuekbrHbXYXERIn4aKdkPSKlyGLsA_A-WEi-OAfXrNVfjhrh7iE6xzq0sg4_vVJoywe4eAJx0fS-Dl3axzTTpYl71Nc7p_NX6iCMmdik0pAuYJegBcTckE3AoYEg4K99AM_JaaKIblsbFh8-3LxnemeNf7UwOczaGGvjS6UzGVI0Odf9lKcPIwYhuTxM5CaNMXTZQ7xq4_yTfC3kPWtE4hFT34UJJflZBiLrxG4OsYxkHw_n5vKgmpspB3GfYuYTWhkDKiE8CYtyg87mhhdXRoRGF0YViUSZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2NBAAAAC_igEfOMCk0VgAYXER-e3H0AEDIBRoyihvjNZOR2yfjLPhulAQIDJiABIVggIXUM4qBXox--h7XwLrTlN4oPj-8bE27wjXlEZIRHL4kiWCBFllqpZSGGRUTgbLTjR5_H4oUr0SJIm3oE659m5sVxUw"
  @encoded_client_data_json "eyJjaGFsbGVuZ2UiOiJCaXo1emxMTU9Cc3M3bWhnaDBOZUR3U0JmU0RBd3RCUmRJWllOWVFMRVlrIiwib3JpZ2luIjoiaHR0cDovL2xvY2FsaG9zdDo0MDAwIiwidHlwZSI6IndlYmF1dGhuLmNyZWF0ZSJ9"
  @origin "http://localhost:4000"
  @challenge "Biz5zlLMOBss7mhgh0NeDwSBfSDAwtBRdIZYNYQLEYk"
  @rp_id "localhost"
  @rp_id_invalid "localhost2"

  # for actual authenticator's log
  @sample_origin "https://example.com"
  @sample_challenge "KM5P053z9HKDKnfDBCdE6g"
  @sample_rp_id "example.com"

  # keychain
  @encoded_attestation_object_keychain "o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YViYo3mm9u6vuaVeN4wRgDTidR5oL6ufLTCrE9ISVYbOGUddAAAAAAAAAAAAAAAAAAAAAAAAAAAAFCPmvJjrA9Cj6TU2H1Oa2r8fB9pGpQECAyYgASFYICdFZVoxrv4JsVRQRND88TV_Q917IgdcpF2jDg4cFelXIlgg5hQAmXqwfBISWno5v4dk1byQ0iUiq2P63yb1PfrFHmc"
  @encoded_client_data_json_keychain "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiS001UDA1M3o5SEtES25mREJDZEU2ZyIsIm9yaWdpbiI6Imh0dHBzOi8vZXhhbXBsZS5jb20iLCJjcm9zc09yaWdpbiI6ZmFsc2V9"

  # Chrome on MacOS
  @encoded_attestation_object_chrome "o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YViko3mm9u6vuaVeN4wRgDTidR5oL6ufLTCrE9ISVYbOGUdFAAAAAK3OAAI1vMYKZIsLJfHwVQMAILv_1TM4JzTox-FHSHgOFEymS7zmPRK8YgtpTR_9GUUbpQECAyYgASFYIBE0VulC_XRULa4FpJ7MqvWPluXIOHWvwqq3N64Wu8lhIlggVpcik5uSvSvNTdlL2Okjjtu4bE-u1OAp8to2saFVa1M"
  @encoded_client_data_json_chrome "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiS001UDA1M3o5SEtES25mREJDZEU2ZyIsIm9yaWdpbiI6Imh0dHBzOi8vZXhhbXBsZS5jb20iLCJjcm9zc09yaWdpbiI6ZmFsc2V9"

  describe "basic" do
    test "validate_client_data_json" do
      assert {:ok, _client_data_json} =
               Register.validate_client_data_json(%{
                 client_data_json: @encoded_client_data_json,
                 origin: @origin,
                 challenge: @challenge
               })
    end

    test "validate_attestation_object" do
      assert {:ok, _storable_public_key = %StorablePublicKey{}, _attestation_object} =
               Register.validate_attestation_object(%{
                 attestation_object: @encoded_attestation_object,
                 client_data_json: @encoded_client_data_json,
                 rp_id: @rp_id,
                 up_required: true,
                 uv_required: false
               })

      assert {:error, :invalid_rp_id_hash} ==
               Register.validate_attestation_object(%{
                 attestation_object: @encoded_attestation_object,
                 client_data_json: @encoded_client_data_json,
                 rp_id: @rp_id_invalid,
                 up_required: true,
                 uv_required: false
               })

      assert {:error, :uv_required} ==
               Register.validate_attestation_object(%{
                 attestation_object: @encoded_attestation_object,
                 client_data_json: @encoded_client_data_json,
                 rp_id: @rp_id,
                 up_required: true,
                 uv_required: true
               })
    end
  end

  describe "actual authenticator's log" do
    test "keychain" do
      assert {:ok, _client_data_json} =
               Register.validate_client_data_json(%{
                 client_data_json: @encoded_client_data_json_keychain,
                 origin: @sample_origin,
                 challenge: @sample_challenge
               })

      assert {:ok, storable_public_key = %StorablePublicKey{}, attestation_object} =
               Register.validate_attestation_object(%{
                 attestation_object: @encoded_attestation_object_keychain,
                 client_data_json: @encoded_client_data_json_keychain,
                 rp_id: @sample_rp_id,
                 up_required: true,
                 uv_required: false
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
             } = storable_public_key

      assert %WebAuthnLite.AttestationObject{
               auth_data: %WebAuthnLite.AuthenticatorData{
                 rp_id_hash: "o3mm9u6vuaVeN4wRgDTidR5oL6ufLTCrE9ISVYbOGUc",
                 flags: %WebAuthnLite.AuthenticatorData.Flags{
                   flags: "]",
                   up: true,
                   uv: true,
                   be: true,
                   bs: true,
                   at: true,
                   ed: false
                 },
                 sign_count: 0,
                 raw: _,
                 attested_credential_data: %WebAuthnLite.AttestedCredentialData{
                   aaguid: "00000000-0000-0000-0000-000000000000",
                   authenticator_name: nil,
                   credential_id: "I-a8mOsD0KPpNTYfU5ravx8H2kY",
                   credential_public_key: %WebAuthnLite.CredentialPublicKey.ES256{
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
                   raw: _,
                   extensions: nil
                 },
                 extensions: nil
               },
               fmt: "none",
               att_stmt: %{},
               raw: _
             } = attestation_object
    end

    test "chrome" do
      assert {:ok, _client_data_json} =
               Register.validate_client_data_json(%{
                 client_data_json: @encoded_client_data_json_chrome,
                 origin: @sample_origin,
                 challenge: @sample_challenge
               })

      assert {:ok, storable_public_key = %StorablePublicKey{}, attestation_object} =
               Register.validate_attestation_object(%{
                 attestation_object: @encoded_attestation_object_chrome,
                 client_data_json: @encoded_client_data_json_chrome,
                 rp_id: @sample_rp_id,
                 up_required: true,
                 uv_required: false
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
             } = storable_public_key

      assert %WebAuthnLite.AttestationObject{
               auth_data: %WebAuthnLite.AuthenticatorData{
                 rp_id_hash: "o3mm9u6vuaVeN4wRgDTidR5oL6ufLTCrE9ISVYbOGUc",
                 flags: %WebAuthnLite.AuthenticatorData.Flags{
                   flags: "E",
                   up: true,
                   uv: true,
                   be: false,
                   bs: false,
                   at: true,
                   ed: false
                 },
                 sign_count: 0,
                 raw: _,
                 attested_credential_data: %WebAuthnLite.AttestedCredentialData{
                   aaguid: "adce0002-35bc-c60a-648b-0b25f1f05503",
                   authenticator_name: "Chrome on Mac",
                   credential_id: "u__VMzgnNOjH4UdIeA4UTKZLvOY9ErxiC2lNH_0ZRRs",
                   credential_public_key: %WebAuthnLite.CredentialPublicKey.ES256{
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
                   raw: _,
                   extensions: nil
                 },
                 extensions: nil
               },
               fmt: "none",
               att_stmt: %{},
               raw: _
             } = attestation_object
    end
  end
end
