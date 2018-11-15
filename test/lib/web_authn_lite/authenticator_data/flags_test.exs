defmodule WebAuthnLite.AuthenticatorData.FlagsTest do
  use ExUnit.Case, async: false
  alias WebAuthnLite.AuthenticatorData.Flags
  doctest Flags

  test "from_binary" do
    assert {:ok,
            %Flags{
              ed: true,
              at: true,
              uv: true,
              up: true,
              flags: <<207>>
            }} ==
             <<1::size(1), 1::size(1), 1::size(3), 1::size(1), 1::size(1), 1::size(1)>>
             |> Flags.from_binary()

    assert {:ok,
            %Flags{
              ed: false,
              at: true,
              uv: true,
              up: true,
              flags: "O"
            }} ==
             <<0::size(1), 1::size(1), 1::size(3), 1::size(1), 1::size(1), 1::size(1)>>
             |> Flags.from_binary()

    assert {:ok,
            %Flags{
              ed: false,
              at: false,
              uv: true,
              up: true,
              flags: <<15>>
            }} ==
             <<0::size(1), 0::size(1), 1::size(3), 1::size(1), 1::size(1), 1::size(1)>>
             |> Flags.from_binary()

    assert {:ok,
            %Flags{
              ed: false,
              at: false,
              uv: false,
              up: true,
              flags: <<3>>
            }} ==
             <<0::size(1), 0::size(1), 0::size(3), 0::size(1), 1::size(1), 1::size(1)>>
             |> Flags.from_binary()

    assert {:ok,
            %Flags{
              ed: false,
              at: false,
              uv: false,
              up: false,
              flags: <<0>>
            }} ==
             <<0::size(1), 0::size(1), 0::size(3), 0::size(1), 0::size(1), 0::size(1)>>
             |> Flags.from_binary()
  end
end
