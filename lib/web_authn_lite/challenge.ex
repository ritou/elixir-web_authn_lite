defmodule WebAuthnLite.Challenge do
  @moduledoc """
  Base64 encoded challenge generator
  """
  def generate_base64_url_encoded_challenge() do
    :crypto.strong_rand_bytes(32) |> Base.url_encode64(padding: false)
  end
end