defmodule WebAuthnLite.UserHandle do
  @moduledoc """
  userHandle Parser
  """

  @spec decode(base64_url_encoded_user_handle :: String.t()) :: String.test()
  def decode(base64_url_encoded_user_handle) do
    try do
      {:ok, base64_url_encoded_user_handle |> Base.url_decode64!(padding: false)}
    rescue
      _ -> {:error, :invalid_format}
    end
  end
end
