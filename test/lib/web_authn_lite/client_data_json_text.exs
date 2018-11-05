defmodule WebAuthnLite.ClientDataJSONTest do
  use ExUnit.Case, async: false
  alias WebAuthnLite.ClientDataJSON

  @valid_encoded_client_data_json "eyJjaGFsbGVuZ2UiOiJhX1Q3TWtFMW8xVW1mWWZDWGFWVkNJcUhFYmpQbXdBUXAzbXNIRnRaaTkwIiwib3JpZ2luIjoiaHR0cDovL2xvY2FsaG9zdDo0MDAwIiwidHlwZSI6IndlYmF1dGhuLmNyZWF0ZSJ9"
  @invalid_encoded_client_data_json "invalid"

  @valid_challenge "a_T7MkE1o1UmfYfCXaVVCIqHEbjPmwAQp3msHFtZi90"
  @valid_origin "http://localhost:4000"
  @valid_raw ~s({\"challenge\":\"a_T7MkE1o1UmfYfCXaVVCIqHEbjPmwAQp3msHFtZi90\",\"origin\":\"http://localhost:4000\",\"type\":\"webauthn.create\"})
  @valid_type "webauthn.create"

  test "decode" do
    assert {:ok, client_data} = ClientDataJSON.decode(@valid_encoded_client_data_json)
    assert client_data.challenge == @valid_challenge
    assert client_data.origin == @valid_origin
    assert client_data.type == @valid_type
    assert client_data.raw == @valid_raw

    assert {:error, :invalid_format} == ClientDataJSON.decode(@invalid_encoded_client_data_json)
  end

  test "validate" do
    assert {:ok, _} = ClientDataJSON.validate(@valid_encoded_client_data_json, @valid_type, @valid_origin, @valid_challenge)
    assert {:error, :invalid_format} == ClientDataJSON.validate(@invalid_encoded_client_data_json, @valid_type, @valid_origin, @valid_challenge)
    assert {:error, :invalid_type} == ClientDataJSON.validate(@valid_encoded_client_data_json, "invalid", @valid_origin, @valid_challenge)
    assert {:error, :invalid_origin} == ClientDataJSON.validate(@valid_encoded_client_data_json, @valid_type, "invalid", @valid_challenge)
    assert {:error, :invalid_challenge} == ClientDataJSON.validate(@valid_encoded_client_data_json, @valid_type, @valid_origin, "invalid")
  end

end
