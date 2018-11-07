defmodule WebAuthnLite.AuthenticatorData.Flags do
  @moduledoc """
  Authenticator Flags
  """

  defstruct [:flags, :up, :uv, :at, :ed]

  @type t :: %__MODULE__{
          flags: binary,
          up: boolean,
          uv: boolean,
          at: boolean,
          ed: boolean
        }

  @flags_byte_size 1

  def decode(flags) do
    with true <- flags |> byte_size() == @flags_byte_size,
         <<up::size(1), _rfu1::size(1), uv::size(1), _rfu2::size(3), at::size(1), ed::size(1)>> <- flags
    do
      {:ok, %__MODULE__{flags: flags, up: up == 1, uv: uv == 1, at: at == 1, ed: ed == 1}}
    else
      _ -> {:error, :invalid_format}
    end
  end

end