defmodule WebAuthnLite.Challenge do
  @moduledoc """
  Base64 encoded challenge generator

  ```
  In order to prevent replay attacks, the challenges MUST contain enough entropy to make guessing them infeasible. Challenges SHOULD therefore be at least 16 bytes long.
  ```
  https://www.w3.org/TR/webauthn/#cryptographic-challenges
  """

  @doc """
  generate base64 URL encoded random bytes string.

    iex> WebAuthnLite.Challenge.generate_base64_url_encoded_challenge()
    "d2IFFBIaBhPDz2_J-_hlyA"
    iex> challenge = WebAuthnLite.Challenge.generate_base64_url_encoded_challenge()
    "b963p5I0bvamfimxpAxMkw"
    iex> challenge |> Base.url_decode64!(padding: false)
    <<111, 222, 183, 167, 146, 52, 110, 246, 166, 126, 41, 177, 164, 12, 76, 147>>
    iex> challenge |> Base.url_decode64!(padding: false) |> byte_size()
    16

    iex> challenge = WebAuthnLite.Challenge.generate_base64_url_encoded_challenge(100)
    "NsUXHZUEyNQkTSEV-zLqT232fopJHKnS4nJLI4r-og0JGQAvHyw97xBO4D4izrrZcTAcA_GX2yYTE-U-yVVFOXWXf5MepHR1rAOT0E2FG7hjSD77QzoDZl1o-AJYaplF2zG9Gw"
    iex> challenge |> Base.url_decode64!(padding: false) |> byte_size()
    100

  """
  @spec generate_base64_url_encoded_challenge(bytes :: integer) :: String.t()
  def generate_base64_url_encoded_challenge(bytes \\ 16)
  def generate_base64_url_encoded_challenge(bytes) when bytes < 16, do: nil

  def generate_base64_url_encoded_challenge(bytes) do
    :crypto.strong_rand_bytes(bytes) |> Base.url_encode64(padding: false)
  end
end
