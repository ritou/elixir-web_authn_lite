defmodule WebAuthnLite.ClientDataJSONTest do
  use ExUnit.Case, async: false

  alias WebAuthnLite.AuthenticatorData
  alias WebAuthnLite.AuthenticatorData.Flags

  doctest AuthenticatorData
  doctest Flags

  @valid_encoded_authenticator_data "SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MBAAAAGw"
  @invalid_encoded_authenticator_data "invalid"

  @encoded_authenticator_data_with_attested_credential_data "SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2NBAAAAC_igEfOMCk0VgAYXER-e3H0AEDIBRoyihvjNZOR2yfjLPhulAQIDJiABIVggIXUM4qBXox--h7XwLrTlN4oPj-8bE27wjXlEZIRHL4kiWCBFllqpZSGGRUTgbLTjR5_H4oUr0SJIm3oE659m5sVxUw"

  test "decode, from_binary" do
    assert {:ok, authenticator_data} = AuthenticatorData.decode(@valid_encoded_authenticator_data)

    assert authenticator_data == %WebAuthnLite.AuthenticatorData{
             flags: %Flags{
               at: false,
               ed: false,
               flags: <<1>>,
               up: true,
               uv: false
             },
             raw:
               <<73, 150, 13, 229, 136, 14, 140, 104, 116, 52, 23, 15, 100, 118, 96, 91, 143, 228,
                 174, 185, 162, 134, 50, 199, 153, 92, 243, 186, 131, 29, 151, 99, 1, 0, 0, 0,
                 27>>,
             rp_id_hash: "SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2M",
             sign_count: 27,
             attested_credential_data: nil,
             extensions: nil
           }

    assert {:ok, authenticator_data} == AuthenticatorData.from_binary(authenticator_data.raw)

    assert {:error, :invalid_authenticator_data} ==
             AuthenticatorData.decode(@invalid_encoded_authenticator_data)

    assert {:ok, authenticator_data} =
             AuthenticatorData.decode(@encoded_authenticator_data_with_attested_credential_data)

    refute is_nil(authenticator_data.attested_credential_data)
  end

  test "rp_id_hash" do
    assert "SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2M" ==
             AuthenticatorData.rp_id_hash("localhost")
  end
end
