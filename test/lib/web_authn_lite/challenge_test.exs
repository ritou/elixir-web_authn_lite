defmodule WebAuthnLite.ChallengeTest do
  use ExUnit.Case, async: false

  alias WebAuthnLite.Challenge

  test "generate_base64_url_encoded_challenge" do
    assert challenge = Challenge.generate_base64_url_encoded_challenge()
    assert 32 == challenge |> Base.url_decode64!(padding: false) |> byte_size()
  end
end