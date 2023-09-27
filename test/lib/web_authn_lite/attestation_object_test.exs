defmodule WebAuthnLite.AttestationObjectTest do
  use ExUnit.Case, async: false

  alias WebAuthnLite.AttestationObject
  doctest AttestationObject

  @es256_encoded_attestation_object "o2NmbXRmcGFja2VkZ2F0dFN0bXSjY2FsZyZjc2lnWEcwRQIgA_2zNZ2yCRDELCX545G4y5ZG7R2LSuz11pw_fgueVggCIQDEY3H5X93IE-pmNvJFCrwOUx6_ljzjBq3jwEYsH-_khWN4NWOBWQLCMIICvjCCAaagAwIBAgIEdIb9wjANBgkqhkiG9w0BAQsFADAuMSwwKgYDVQQDEyNZdWJpY28gVTJGIFJvb3QgQ0EgU2VyaWFsIDQ1NzIwMDYzMTAgFw0xNDA4MDEwMDAwMDBaGA8yMDUwMDkwNDAwMDAwMFowbzELMAkGA1UEBhMCU0UxEjAQBgNVBAoMCVl1YmljbyBBQjEiMCAGA1UECwwZQXV0aGVudGljYXRvciBBdHRlc3RhdGlvbjEoMCYGA1UEAwwfWXViaWNvIFUyRiBFRSBTZXJpYWwgMTk1NTAwMzg0MjBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABJVd8633JH0xde_9nMTzGk6HjrrhgQlWYVD7OIsuX2Unv1dAmqWBpQ0KxS8YRFwKE1SKE1PIpOWacE5SO8BN6-2jbDBqMCIGCSsGAQQBgsQKAgQVMS4zLjYuMS40LjEuNDE0ODIuMS4xMBMGCysGAQQBguUcAgEBBAQDAgUgMCEGCysGAQQBguUcAQEEBBIEEPigEfOMCk0VgAYXER-e3H0wDAYDVR0TAQH_BAIwADANBgkqhkiG9w0BAQsFAAOCAQEAMVxIgOaaUn44Zom9af0KqG9J655OhUVBVW-q0As6AIod3AH5bHb2aDYakeIyyBCnnGMHTJtuekbrHbXYXERIn4aKdkPSKlyGLsA_A-WEi-OAfXrNVfjhrh7iE6xzq0sg4_vVJoywe4eAJx0fS-Dl3axzTTpYl71Nc7p_NX6iCMmdik0pAuYJegBcTckE3AoYEg4K99AM_JaaKIblsbFh8-3LxnemeNf7UwOczaGGvjS6UzGVI0Odf9lKcPIwYhuTxM5CaNMXTZQ7xq4_yTfC3kPWtE4hFT34UJJflZBiLrxG4OsYxkHw_n5vKgmpspB3GfYuYTWhkDKiE8CYtyg87mhhdXRoRGF0YViUSZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2NBAAAAC_igEfOMCk0VgAYXER-e3H0AEDIBRoyihvjNZOR2yfjLPhulAQIDJiABIVggIXUM4qBXox--h7XwLrTlN4oPj-8bE27wjXlEZIRHL4kiWCBFllqpZSGGRUTgbLTjR5_H4oUr0SJIm3oE659m5sVxUw"
  @rs256_encoded_attestation_object "o2NmbXRmcGFja2VkZ2F0dFN0bXSjY2FsZyZjc2lnWEcwRQIgThpTAf8MepxmcrpuGcSg3zIh1YlpFbEiDyzR6OvZ5NACIQC13zBxySK7g3nYXjt1DSY_uUlSdGVqzUeh7YZ2BAcAPWN4NWOBWQLCMIICvjCCAaagAwIBAgIEdIb9wjANBgkqhkiG9w0BAQsFADAuMSwwKgYDVQQDEyNZdWJpY28gVTJGIFJvb3QgQ0EgU2VyaWFsIDQ1NzIwMDYzMTAgFw0xNDA4MDEwMDAwMDBaGA8yMDUwMDkwNDAwMDAwMFowbzELMAkGA1UEBhMCU0UxEjAQBgNVBAoMCVl1YmljbyBBQjEiMCAGA1UECwwZQXV0aGVudGljYXRvciBBdHRlc3RhdGlvbjEoMCYGA1UEAwwfWXViaWNvIFUyRiBFRSBTZXJpYWwgMTk1NTAwMzg0MjBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABJVd8633JH0xde_9nMTzGk6HjrrhgQlWYVD7OIsuX2Unv1dAmqWBpQ0KxS8YRFwKE1SKE1PIpOWacE5SO8BN6-2jbDBqMCIGCSsGAQQBgsQKAgQVMS4zLjYuMS40LjEuNDE0ODIuMS4xMBMGCysGAQQBguUcAgEBBAQDAgUgMCEGCysGAQQBguUcAQEEBBIEEPigEfOMCk0VgAYXER-e3H0wDAYDVR0TAQH_BAIwADANBgkqhkiG9w0BAQsFAAOCAQEAMVxIgOaaUn44Zom9af0KqG9J655OhUVBVW-q0As6AIod3AH5bHb2aDYakeIyyBCnnGMHTJtuekbrHbXYXERIn4aKdkPSKlyGLsA_A-WEi-OAfXrNVfjhrh7iE6xzq0sg4_vVJoywe4eAJx0fS-Dl3axzTTpYl71Nc7p_NX6iCMmdik0pAuYJegBcTckE3AoYEg4K99AM_JaaKIblsbFh8-3LxnemeNf7UwOczaGGvjS6UzGVI0Odf9lKcPIwYhuTxM5CaNMXTZQ7xq4_yTfC3kPWtE4hFT34UJJflZBiLrxG4OsYxkHw_n5vKgmpspB3GfYuYTWhkDKiE8CYtyg87mhhdXRoRGF0YVkBV0mWDeWIDoxodDQXD2R2YFuP5K65ooYyx5lc87qDHZdjQQAAAAD4oBHzjApNFYAGFxEfntx9ABCUA-lV13qt8KLlxgdRaWgxpAEDAzkBACBZAQDM-x5K_C029zWk9MXsN3f4YY-Mau9qlEdIxpdxDlip1mV2XYzYsBq6feMTT-veag1Nf4vg9pFMHnjhvgEw7lVca3E88jGPXJ3B1gaQv7vOJRhdoIuD5Mt3dsAu9omMmPN3r1IgTbSRUY50fkEZiQmFbu-bVImk4yxltutSIIC4b9cNf2tqxlcBqimUCX2pAJf8xDCJYUsfptO4xNs5qIfDrWiDjzo1qIb7P6a5RYCSfFCecI9roM1ez4YiHTQQFybyyqNOcTTzp3I1iLPcg3A9x3x6OwNtqksf4suaNPmh8XTF8Ba1w60mWmBrrI8eVNCoHMTPa-pSKnQ-MKUAG71NIUMBAAE"

  # 1Password
  @encoded_attestation_object_1password "o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YViUo3mm9u6vuaVeN4wRgDTidR5oL6ufLTCrE9ISVYbOGUddAAAAALraVWanqkAfvZZFYZpVEg0AEBV8RLDI6FzuHWLlgNTqOeWlAQIDJiABIVggMIjD51IGil6-KzaSJwzmzj0YlCyDkkVAV9t7T161Jq4iWCB0JrqhxBybWsBKYFnGqgvIseiao_2Um4nhfzzylw2Gog"

  test "decode" do
    assert {:error, :invalid_attestation_object} = "invalid" |> AttestationObject.decode()

    assert {:ok, attestation_object} =
             @es256_encoded_attestation_object |> AttestationObject.decode()

    assert attestation_object.fmt == "packed"
    refute attestation_object.auth_data |> is_nil()
    # TODO: more tests

    assert {:ok, attestation_object} =
             @rs256_encoded_attestation_object |> AttestationObject.decode()

    assert attestation_object.fmt == "packed"
    refute attestation_object.auth_data |> is_nil()
    # TODO: more tests
  end

  test "passkey" do
    assert {:ok, attestation_object} =
             @encoded_attestation_object_1password |> AttestationObject.decode()

    assert attestation_object.fmt == "none"
    refute attestation_object.auth_data |> is_nil()

    assert attestation_object.auth_data.attested_credential_data.aaguid ==
             "bada5566-a7aa-401f-bd96-45619a55120d"

    assert attestation_object.auth_data.attested_credential_data.authenticator_name == "1Password"
    # TODO: more tests
  end
end
