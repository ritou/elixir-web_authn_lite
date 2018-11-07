defmodule WebAuthnLite.ChallengeTest do
  use ExUnit.Case, async: false

  alias WebAuthnLite.Challenge
  doctest Challenge

  test "generate_base64_url_encoded_challenge" do
    assert nil == Challenge.generate_base64_url_encoded_challenge(15)

    assert 16 ==
             Challenge.generate_base64_url_encoded_challenge()
             |> Base.url_decode64!(padding: false)
             |> byte_size()

    assert 32 ==
             Challenge.generate_base64_url_encoded_challenge(32)
             |> Base.url_decode64!(padding: false)
             |> byte_size()
  end
end
