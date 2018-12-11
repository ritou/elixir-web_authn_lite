defmodule WebAuthnLite.Operation.RegisterTest do
  use ExUnit.Case, async: false

  alias WebAuthnLite.StorablePublicKey
  alias WebAuthnLite.Operation.Register
  # doctest Register

  @encoded_attestation_object "o2NmbXRmcGFja2VkZ2F0dFN0bXSjY2FsZyZjc2lnWEcwRQIgA_2zNZ2yCRDELCX545G4y5ZG7R2LSuz11pw_fgueVggCIQDEY3H5X93IE-pmNvJFCrwOUx6_ljzjBq3jwEYsH-_khWN4NWOBWQLCMIICvjCCAaagAwIBAgIEdIb9wjANBgkqhkiG9w0BAQsFADAuMSwwKgYDVQQDEyNZdWJpY28gVTJGIFJvb3QgQ0EgU2VyaWFsIDQ1NzIwMDYzMTAgFw0xNDA4MDEwMDAwMDBaGA8yMDUwMDkwNDAwMDAwMFowbzELMAkGA1UEBhMCU0UxEjAQBgNVBAoMCVl1YmljbyBBQjEiMCAGA1UECwwZQXV0aGVudGljYXRvciBBdHRlc3RhdGlvbjEoMCYGA1UEAwwfWXViaWNvIFUyRiBFRSBTZXJpYWwgMTk1NTAwMzg0MjBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABJVd8633JH0xde_9nMTzGk6HjrrhgQlWYVD7OIsuX2Unv1dAmqWBpQ0KxS8YRFwKE1SKE1PIpOWacE5SO8BN6-2jbDBqMCIGCSsGAQQBgsQKAgQVMS4zLjYuMS40LjEuNDE0ODIuMS4xMBMGCysGAQQBguUcAgEBBAQDAgUgMCEGCysGAQQBguUcAQEEBBIEEPigEfOMCk0VgAYXER-e3H0wDAYDVR0TAQH_BAIwADANBgkqhkiG9w0BAQsFAAOCAQEAMVxIgOaaUn44Zom9af0KqG9J655OhUVBVW-q0As6AIod3AH5bHb2aDYakeIyyBCnnGMHTJtuekbrHbXYXERIn4aKdkPSKlyGLsA_A-WEi-OAfXrNVfjhrh7iE6xzq0sg4_vVJoywe4eAJx0fS-Dl3axzTTpYl71Nc7p_NX6iCMmdik0pAuYJegBcTckE3AoYEg4K99AM_JaaKIblsbFh8-3LxnemeNf7UwOczaGGvjS6UzGVI0Odf9lKcPIwYhuTxM5CaNMXTZQ7xq4_yTfC3kPWtE4hFT34UJJflZBiLrxG4OsYxkHw_n5vKgmpspB3GfYuYTWhkDKiE8CYtyg87mhhdXRoRGF0YViUSZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2NBAAAAC_igEfOMCk0VgAYXER-e3H0AEDIBRoyihvjNZOR2yfjLPhulAQIDJiABIVggIXUM4qBXox--h7XwLrTlN4oPj-8bE27wjXlEZIRHL4kiWCBFllqpZSGGRUTgbLTjR5_H4oUr0SJIm3oE659m5sVxUw"
  @encoded_client_data_json "eyJjaGFsbGVuZ2UiOiJCaXo1emxMTU9Cc3M3bWhnaDBOZUR3U0JmU0RBd3RCUmRJWllOWVFMRVlrIiwib3JpZ2luIjoiaHR0cDovL2xvY2FsaG9zdDo0MDAwIiwidHlwZSI6IndlYmF1dGhuLmNyZWF0ZSJ9"
  @origin "http://localhost:4000"
  @challenge "Biz5zlLMOBss7mhgh0NeDwSBfSDAwtBRdIZYNYQLEYk"
  @rp_id "localhost"
  @rp_id_invalid "localhost2"

  test "validate_client_data_json" do
    assert {:ok, _client_data_json} =
             Register.validate_client_data_json(%{
               client_data_json: @encoded_client_data_json,
               origin: @origin,
               challenge: @challenge
             })
  end

  test "validate_attestation_object" do
    assert {:ok, storable_public_key = %StorablePublicKey{}, _attestation_object} =
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
