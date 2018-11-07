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

    iex> WebAuthnLite.Challenge.generate_base64_url_encoded_challenge() |> Base.url_decode64!(padding: false) |> byte_size()
    16

    iex> WebAuthnLite.Challenge.generate_base64_url_encoded_challenge(100) |> Base.url_decode64!(padding: false) |> byte_size()
    100

  """
  @spec generate_base64_url_encoded_challenge(bytes :: integer) :: String.t()
  def generate_base64_url_encoded_challenge(bytes \\ 16)
  def generate_base64_url_encoded_challenge(bytes) when bytes < 16, do: nil

  def generate_base64_url_encoded_challenge(bytes) do
    :crypto.strong_rand_bytes(bytes) |> Base.url_encode64(padding: false)
  end
end
