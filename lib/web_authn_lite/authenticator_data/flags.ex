defmodule WebAuthnLite.AuthenticatorData.Flags do
  @moduledoc """
  Struct for authenticator flags

  see https://www.w3.org/TR/webauthn/#flags
  """

  defstruct [:flags, :up, :uv, :be, :bs, :at, :ed]

  @type t :: %__MODULE__{
          flags: binary,
          up: boolean,
          uv: boolean,
          be: boolean,
          bs: boolean,
          at: boolean,
          ed: boolean
        }

  @flags_byte_size 1

  @doc """
  parse bitstring and return struct.
  """
  @spec from_binary(flags :: binary) :: {:ok, t} | {:error, :invalid_format}
  def from_binary(flags) do
    with true <- flags |> byte_size() == @flags_byte_size,
         <<ed::size(1), at::size(1), _rfu2::size(1), bs::size(1), be::size(1), uv::size(1),
           _rfu1::size(1), up::size(1)>> <- flags do
      {:ok,
       %__MODULE__{
         flags: flags,
         up: up == 1,
         uv: uv == 1,
         be: be == 1,
         bs: bs == 1,
         at: at == 1,
         ed: ed == 1
       }}
    else
      _ -> {:error, :invalid_format}
    end
  end
end
