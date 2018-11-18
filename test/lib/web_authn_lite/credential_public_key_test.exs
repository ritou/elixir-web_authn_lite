defmodule WebAuthnLite.CredentialPublicKeyTest do
  use ExUnit.Case, async: false

  alias WebAuthnLite.CredentialPublicKey
  doctest CredentialPublicKey

  @es256_cbor_map %{
    -3 =>
      <<69, 150, 90, 169, 101, 33, 134, 69, 68, 224, 108, 180, 227, 71, 159, 199, 226, 133, 43,
        209, 34, 72, 155, 122, 4, 235, 159, 102, 230, 197, 113, 83>>,
    -2 =>
      <<33, 117, 12, 226, 160, 87, 163, 31, 190, 135, 181, 240, 46, 180, 229, 55, 138, 15, 143,
        239, 27, 19, 110, 240, 141, 121, 68, 100, 132, 71, 47, 137>>,
    -1 => 1,
    1 => 2,
    3 => -7
  }

  @rs256_cbor_map %{
    -2 => <<1, 0, 1>>,
    -1 =>
      "zPseSvwtNvc1pPTF7Dd3-GGPjGrvapRHSMaXcQ5YqdZldl2M2LAaun3jE0_r3moNTX-L4PaRTB544b4BMO5VXGtxPPIxj1ydwdYGkL-7ziUYXaCLg-TLd3bALvaJjJjzd69SIE20kVGOdH5BGYkJhW7vm1SJpOMsZbbrUiCAuG_XDX9rasZXAaoplAl9qQCX_MQwiWFLH6bTuMTbOaiHw61og486NaiG-z-muUWAknxQnnCPa6DNXs-GIh00EBcm8sqjTnE086dyNYiz3INwPcd8ejsDbapLH-LLmjT5ofF0xfAWtcOtJlpga6yPHlTQqBzEz2vqUip0PjClABu9TQ"
      |> Base.url_decode64!(padding: false),
    1 => 3,
    3 => -257
  }

  test "ES256" do
    assert credential_public_key = CredentialPublicKey.from_cbor_map(@es256_cbor_map)
    refute is_nil(credential_public_key)
    assert credential_public_key.digest_type == :sha256

    assert credential_public_key.map == %{
             "crv" => "P-256",
             "kty" => "EC",
             "x" => "IXUM4qBXox++h7XwLrTlN4oPj+8bE27wjXlEZIRHL4k=",
             "y" => "RZZaqWUhhkVE4Gy040efx+KFK9EiSJt6BOufZubFcVM="
           }
  end

  test "RS256" do
    assert credential_public_key = CredentialPublicKey.from_cbor_map(@rs256_cbor_map)
    refute is_nil(credential_public_key)
    assert credential_public_key.digest_type == :sha256

    assert credential_public_key.map == %{
             "e" => "AQAB",
             "kty" => "RSA",
             "n" =>
               "zPseSvwtNvc1pPTF7Dd3+GGPjGrvapRHSMaXcQ5YqdZldl2M2LAaun3jE0/r3moNTX+L4PaRTB544b4BMO5VXGtxPPIxj1ydwdYGkL+7ziUYXaCLg+TLd3bALvaJjJjzd69SIE20kVGOdH5BGYkJhW7vm1SJpOMsZbbrUiCAuG/XDX9rasZXAaoplAl9qQCX/MQwiWFLH6bTuMTbOaiHw61og486NaiG+z+muUWAknxQnnCPa6DNXs+GIh00EBcm8sqjTnE086dyNYiz3INwPcd8ejsDbapLH+LLmjT5ofF0xfAWtcOtJlpga6yPHlTQqBzEz2vqUip0PjClABu9TQ=="
           }
  end
end
