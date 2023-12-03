defmodule WebAuthnLite.CBOR do
  def decode!(value) do
    decode(value)
    |> case do
      {:ok, value} -> value
      _ -> {:error, :invalid_trailing_data}
    end
  end

  def decode(value, opts \\ []) do
    remain = opts[:remain] || false

    if remain do
      do_decode(value)
    else
      case do_decode(value) do
        {:ok, value, _remain} -> {:ok, value}
        error -> error
      end
    end
  end

  defp do_decode(value) do
    case CBOR.decode(value) do
      {:ok, decoded, remain} -> {:ok, decoded, remain}
      _ -> {:error, :invalid_trailing_data}
    end
  end
end
