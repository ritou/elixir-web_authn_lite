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
  @encoded_attestation_object_keychain "o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YViYo3mm9u6vuaVeN4wRgDTidR5oL6ufLTCrE9ISVYbOGUddAAAAAPv8MAcVTk7MjAtuAgVX170AFOZrpU9l6H4OXBryz5cC0G952b8dpQECAyYgASFYIGAhP4smwwBQ-NoVi8E3pV1vQ-gOzszN_oJGd-_-at93IlggQyg3-uNndISiY8sTRVYopaxSAiGoINQwcYbC1X8pZPI"
  @encoded_client_data_json_keychain "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiS001UDA1M3o5SEtES25mREJDZEU2ZyIsIm9yaWdpbiI6Imh0dHBzOi8vZXhhbXBsZS5jb20iLCJjcm9zc09yaWdpbiI6ZmFsc2V9"

  # Chrome on MacOS
  @encoded_attestation_object_chrome "o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YViko3mm9u6vuaVeN4wRgDTidR5oL6ufLTCrE9ISVYbOGUdFAAAAAK3OAAI1vMYKZIsLJfHwVQMAILv_1TM4JzTox-FHSHgOFEymS7zmPRK8YgtpTR_9GUUbpQECAyYgASFYIBE0VulC_XRULa4FpJ7MqvWPluXIOHWvwqq3N64Wu8lhIlggVpcik5uSvSvNTdlL2Okjjtu4bE-u1OAp8to2saFVa1M"
  @encoded_client_data_json_chrome "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiS001UDA1M3o5SEtES25mREJDZEU2ZyIsIm9yaWdpbiI6Imh0dHBzOi8vZXhhbXBsZS5jb20iLCJjcm9zc09yaWdpbiI6ZmFsc2V9"

  # 1Password
  @encoded_attestation_object_1password "o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YViUo3mm9u6vuaVeN4wRgDTidR5oL6ufLTCrE9ISVYbOGUddAAAAALraVWanqkAfvZZFYZpVEg0AEGBXeEQ8yxQazz5IPwZqhE2lAQIDJiABIVggvWFLkJMYDEDGBi6yc8ScvDfjq2kouAGlmQYdx9JunzIiWCDXAfwyGybtPLjHWFj0vR7bWVq6RvNuEq4xGW9Mf6eCcw"
  @encoded_client_data_json_1password "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiS001UDA1M3o5SEtES25mREJDZEU2ZyIsIm9yaWdpbiI6Imh0dHBzOi8vZXhhbXBsZS5jb20ifQ"

  # Titan Security Key
  @encoded_attestation_object_titan "o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YViio3mm9u6vuaVeN4wRgDTidR5oL6ufLTCrE9ISVYbOGUfFAAAABAAAAAAAAAAAAAAAAAAAAAAAEAABALkUNLt3WUXkiu0RtI2lAQIDJiABIVggyWB-u2ZIJnvTOIH-hKxya4JkDJNPj6wapbzsYA_7jmoiWCDLAU9vy_ZOkd_Gz_1auXTDxRSJhNsPdyiYcIV_gWnCjKFrY3JlZFByb3RlY3QC"
  @encoded_client_data_json_titan "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiS001UDA1M3o5SEtES25mREJDZEU2ZyIsIm9yaWdpbiI6Imh0dHBzOi8vZXhhbXBsZS5jb20iLCJjcm9zc09yaWdpbiI6ZmFsc2V9"

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
               credential_id: "5mulT2Xofg5cGvLPlwLQb3nZvx0",
               public_key: %WebAuthnLite.CredentialPublicKey.ES256{
                 key: {{:ECPoint, _}, {:namedCurve, {1, 2, 840, 10045, 3, 1, 7}}},
                 digest_type: :sha256,
                 map: %{
                   "crv" => "P-256",
                   "kty" => "EC",
                   "x" => "YCE_iybDAFD42hWLwTelXW9D6A7OzM3-gkZ37_5q33c",
                   "y" => "Qyg3-uNndISiY8sTRVYopaxSAiGoINQwcYbC1X8pZPI"
                 },
                 json:
                   "{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"YCE_iybDAFD42hWLwTelXW9D6A7OzM3-gkZ37_5q33c\",\"y\":\"Qyg3-uNndISiY8sTRVYopaxSAiGoINQwcYbC1X8pZPI\"}"
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
                   aaguid: "fbfc3007-154e-4ecc-8c0b-6e020557d7bd",
                   authenticator_name: "iCloud Keychain",
                   credential_id: "5mulT2Xofg5cGvLPlwLQb3nZvx0",
                   credential_public_key: %WebAuthnLite.CredentialPublicKey.ES256{
                     key: {{:ECPoint, _}, {:namedCurve, {1, 2, 840, 10045, 3, 1, 7}}},
                     digest_type: :sha256,
                     map: %{
                       "crv" => "P-256",
                       "kty" => "EC",
                       "x" => "YCE_iybDAFD42hWLwTelXW9D6A7OzM3-gkZ37_5q33c",
                       "y" => "Qyg3-uNndISiY8sTRVYopaxSAiGoINQwcYbC1X8pZPI"
                     },
                     json:
                       "{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"YCE_iybDAFD42hWLwTelXW9D6A7OzM3-gkZ37_5q33c\",\"y\":\"Qyg3-uNndISiY8sTRVYopaxSAiGoINQwcYbC1X8pZPI\"}"
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

    test "1password" do
      assert {:ok, _client_data_json} =
               Register.validate_client_data_json(%{
                 client_data_json: @encoded_client_data_json_1password,
                 origin: @sample_origin,
                 challenge: @sample_challenge
               })

      assert {:ok, storable_public_key = %StorablePublicKey{}, attestation_object} =
               Register.validate_attestation_object(%{
                 attestation_object: @encoded_attestation_object_1password,
                 client_data_json: @encoded_client_data_json_1password,
                 rp_id: @sample_rp_id,
                 up_required: true,
                 uv_required: false
               })

      assert %WebAuthnLite.StorablePublicKey{
               credential_id: "YFd4RDzLFBrPPkg_BmqETQ",
               public_key: %WebAuthnLite.CredentialPublicKey.ES256{
                 key: {{:ECPoint, _}, {:namedCurve, {1, 2, 840, 10045, 3, 1, 7}}},
                 digest_type: :sha256,
                 map: %{
                   "crv" => "P-256",
                   "kty" => "EC",
                   "x" => "vWFLkJMYDEDGBi6yc8ScvDfjq2kouAGlmQYdx9JunzI",
                   "y" => "1wH8Mhsm7Ty4x1hY9L0e21laukbzbhKuMRlvTH-ngnM"
                 },
                 json:
                   "{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"vWFLkJMYDEDGBi6yc8ScvDfjq2kouAGlmQYdx9JunzI\",\"y\":\"1wH8Mhsm7Ty4x1hY9L0e21laukbzbhKuMRlvTH-ngnM\"}"
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
                   aaguid: "bada5566-a7aa-401f-bd96-45619a55120d",
                   authenticator_name: "1Password",
                   credential_id: "YFd4RDzLFBrPPkg_BmqETQ",
                   credential_public_key: %WebAuthnLite.CredentialPublicKey.ES256{
                     key: {{:ECPoint, _}, {:namedCurve, {1, 2, 840, 10045, 3, 1, 7}}},
                     digest_type: :sha256,
                     map: %{
                       "crv" => "P-256",
                       "kty" => "EC",
                       "x" => "vWFLkJMYDEDGBi6yc8ScvDfjq2kouAGlmQYdx9JunzI",
                       "y" => "1wH8Mhsm7Ty4x1hY9L0e21laukbzbhKuMRlvTH-ngnM"
                     },
                     json:
                       "{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"vWFLkJMYDEDGBi6yc8ScvDfjq2kouAGlmQYdx9JunzI\",\"y\":\"1wH8Mhsm7Ty4x1hY9L0e21laukbzbhKuMRlvTH-ngnM\"}"
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

    test "titan" do
      assert {:ok, _client_data_json} =
               Register.validate_client_data_json(%{
                 client_data_json: @encoded_client_data_json_titan,
                 origin: @sample_origin,
                 challenge: @sample_challenge
               })

      assert {:ok, storable_public_key = %StorablePublicKey{}, attestation_object} =
               Register.validate_attestation_object(%{
                 attestation_object: @encoded_attestation_object_titan,
                 client_data_json: @encoded_client_data_json_titan,
                 rp_id: @sample_rp_id,
                 up_required: true,
                 uv_required: false
               })

      assert %WebAuthnLite.StorablePublicKey{
               credential_id: "AAEAuRQ0u3dZReSK7RG0jQ",
               public_key: %WebAuthnLite.CredentialPublicKey.ES256{
                 key: {{:ECPoint, _}, {:namedCurve, {1, 2, 840, 10045, 3, 1, 7}}},
                 digest_type: :sha256,
                 map: %{
                   "crv" => "P-256",
                   "kty" => "EC",
                   "x" => "yWB-u2ZIJnvTOIH-hKxya4JkDJNPj6wapbzsYA_7jmo",
                   "y" => "ywFPb8v2TpHfxs_9Wrl0w8UUiYTbD3comHCFf4Fpwow"
                 },
                 json:
                   "{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"yWB-u2ZIJnvTOIH-hKxya4JkDJNPj6wapbzsYA_7jmo\",\"y\":\"ywFPb8v2TpHfxs_9Wrl0w8UUiYTbD3comHCFf4Fpwow\"}"
               },
               sign_count: 4
             } = storable_public_key

      assert %WebAuthnLite.AttestationObject{
               auth_data: %WebAuthnLite.AuthenticatorData{
                 rp_id_hash: "o3mm9u6vuaVeN4wRgDTidR5oL6ufLTCrE9ISVYbOGUc",
                 flags: %WebAuthnLite.AuthenticatorData.Flags{
                   flags: <<197>>,
                   up: true,
                   uv: true,
                   be: false,
                   bs: false,
                   at: true,
                   ed: true
                 },
                 sign_count: 4,
                 raw: _,
                 attested_credential_data: %WebAuthnLite.AttestedCredentialData{
                   aaguid: "00000000-0000-0000-0000-000000000000",
                   authenticator_name: nil,
                   credential_id: "AAEAuRQ0u3dZReSK7RG0jQ",
                   credential_public_key: %WebAuthnLite.CredentialPublicKey.ES256{
                     key: {{:ECPoint, _}, {:namedCurve, {1, 2, 840, 10045, 3, 1, 7}}},
                     digest_type: :sha256,
                     map: %{
                       "crv" => "P-256",
                       "kty" => "EC",
                       "x" => "yWB-u2ZIJnvTOIH-hKxya4JkDJNPj6wapbzsYA_7jmo",
                       "y" => "ywFPb8v2TpHfxs_9Wrl0w8UUiYTbD3comHCFf4Fpwow"
                     },
                     json:
                       "{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"yWB-u2ZIJnvTOIH-hKxya4JkDJNPj6wapbzsYA_7jmo\",\"y\":\"ywFPb8v2TpHfxs_9Wrl0w8UUiYTbD3comHCFf4Fpwow\"}"
                   },
                   raw: _,
                   extensions: %{"credProtect" => 2}
                 },
                 extensions: %{"credProtect" => 2}
               },
               fmt: "none",
               att_stmt: %{},
               raw: _
             } = attestation_object
    end
  end
end
