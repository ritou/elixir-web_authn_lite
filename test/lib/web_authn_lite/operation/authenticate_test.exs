defmodule WebAuthnLite.Operation.AuthenticateTest do
  use ExUnit.Case, async: false

  alias WebAuthnLite.StorablePublicKey
  alias WebAuthnLite.Operation.Authenticate
  # doctest Authenticate

  @encoded_attestation_object "o2NmbXRmcGFja2VkZ2F0dFN0bXSjY2FsZyZjc2lnWEcwRQIgA_2zNZ2yCRDELCX545G4y5ZG7R2LSuz11pw_fgueVggCIQDEY3H5X93IE-pmNvJFCrwOUx6_ljzjBq3jwEYsH-_khWN4NWOBWQLCMIICvjCCAaagAwIBAgIEdIb9wjANBgkqhkiG9w0BAQsFADAuMSwwKgYDVQQDEyNZdWJpY28gVTJGIFJvb3QgQ0EgU2VyaWFsIDQ1NzIwMDYzMTAgFw0xNDA4MDEwMDAwMDBaGA8yMDUwMDkwNDAwMDAwMFowbzELMAkGA1UEBhMCU0UxEjAQBgNVBAoMCVl1YmljbyBBQjEiMCAGA1UECwwZQXV0aGVudGljYXRvciBBdHRlc3RhdGlvbjEoMCYGA1UEAwwfWXViaWNvIFUyRiBFRSBTZXJpYWwgMTk1NTAwMzg0MjBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABJVd8633JH0xde_9nMTzGk6HjrrhgQlWYVD7OIsuX2Unv1dAmqWBpQ0KxS8YRFwKE1SKE1PIpOWacE5SO8BN6-2jbDBqMCIGCSsGAQQBgsQKAgQVMS4zLjYuMS40LjEuNDE0ODIuMS4xMBMGCysGAQQBguUcAgEBBAQDAgUgMCEGCysGAQQBguUcAQEEBBIEEPigEfOMCk0VgAYXER-e3H0wDAYDVR0TAQH_BAIwADANBgkqhkiG9w0BAQsFAAOCAQEAMVxIgOaaUn44Zom9af0KqG9J655OhUVBVW-q0As6AIod3AH5bHb2aDYakeIyyBCnnGMHTJtuekbrHbXYXERIn4aKdkPSKlyGLsA_A-WEi-OAfXrNVfjhrh7iE6xzq0sg4_vVJoywe4eAJx0fS-Dl3axzTTpYl71Nc7p_NX6iCMmdik0pAuYJegBcTckE3AoYEg4K99AM_JaaKIblsbFh8-3LxnemeNf7UwOczaGGvjS6UzGVI0Odf9lKcPIwYhuTxM5CaNMXTZQ7xq4_yTfC3kPWtE4hFT34UJJflZBiLrxG4OsYxkHw_n5vKgmpspB3GfYuYTWhkDKiE8CYtyg87mhhdXRoRGF0YViUSZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2NBAAAAC_igEfOMCk0VgAYXER-e3H0AEDIBRoyihvjNZOR2yfjLPhulAQIDJiABIVggIXUM4qBXox--h7XwLrTlN4oPj-8bE27wjXlEZIRHL4kiWCBFllqpZSGGRUTgbLTjR5_H4oUr0SJIm3oE659m5sVxUw"
  @encoded_authenticator_data "SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MBAAAADA"
  @encoded_client_data_json "eyJjaGFsbGVuZ2UiOiJJOV9idk5DRzNNell6Zkc2V0NPNGNhVVUwcnJjbEVNVTJETElnWmVNR3R3Iiwib3JpZ2luIjoiaHR0cDovL2xvY2FsaG9zdDo0MDAwIiwidHlwZSI6IndlYmF1dGhuLmdldCJ9"
  @encoded_signature "MEQCIH22OhUJTVAdjFoNuxcjC4Vz0Ju4N1r378sA6v-DnMugAiAYoWx2s3j6C37Vgfz04Dq_lV9ybFL3JHySPLEXJGrRhw"
  @origin "http://localhost:4000"
  @challenge "I9_bvNCG3MzYzfG6WCO4caUU0rrclEMU2DLIgZeMGtw"
  @rp_id "localhost"
  @credential_id "MgFGjKKG-M1k5HbJ-Ms-Gw"

  test "validate_client_data_json" do
    assert {:ok, _client_data_json} =
             Authenticate.validate_client_data_json(%{
               client_data_json: @encoded_client_data_json,
               origin: @origin,
               challenge: @challenge
             })
  end

  test "validate_authenticator_assertion" do
    {:ok, attestation_object} = WebAuthnLite.AttestationObject.decode(@encoded_attestation_object)

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
