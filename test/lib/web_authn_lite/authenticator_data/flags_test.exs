defmodule WebAuthnLite.AuthenticatorData.FlagsTest do
  use ExUnit.Case, async: false
  alias WebAuthnLite.AuthenticatorData.Flags
  doctest Flags

  test "from_binary" do
    assert {:ok,
            %Flags{
              ed: true,
              at: true,
              bs: true,
              be: true,
              uv: true,
              up: true,
              flags: <<221>>
            }} ==
             <<1::size(1), 1::size(1), 0::size(1), 1::size(1), 1::size(1), 1::size(1), 0::size(1),
               1::size(1)>>
             |> Flags.from_binary()

    assert {:ok,
            %Flags{
              ed: false,
              at: true,
              bs: true,
              be: true,
              uv: true,
              up: true,
              flags: <<93>>
            }} ==
             <<0::size(1), 1::size(1), 0::size(1), 1::size(1), 1::size(1), 1::size(1), 0::size(1),
               1::size(1)>>
             |> Flags.from_binary()

    assert {:ok,
            %Flags{
              ed: false,
              at: false,
              bs: true,
              be: true,
              uv: true,
              up: true,
              flags: <<29>>
            }} ==
             <<0::size(1), 0::size(1), 0::size(1), 1::size(1), 1::size(1), 1::size(1), 0::size(1),
               1::size(1)>>
             |> Flags.from_binary()

    assert {:ok,
            %Flags{
              ed: false,
              at: false,
              bs: false,
              be: true,
              uv: true,
              up: true,
              flags: <<13>>
            }} ==
             <<0::size(1), 0::size(1), 0::size(1), 0::size(1), 1::size(1), 1::size(1), 0::size(1),
               1::size(1)>>
             |> Flags.from_binary()

    assert {:ok,
            %Flags{
              ed: false,
              at: false,
              bs: false,
              be: false,
              uv: true,
              up: true,
              flags: <<5>>
            }} ==
             <<0::size(1), 0::size(1), 0::size(1), 0::size(1), 0::size(1), 1::size(1), 0::size(1),
               1::size(1)>>
             |> Flags.from_binary()

    assert {:ok,
            %Flags{
              ed: false,
              at: false,
              bs: false,
              be: false,
              uv: false,
              up: true,
              flags: <<1>>
            }} ==
             <<0::size(1), 0::size(1), 0::size(1), 0::size(1), 0::size(1), 0::size(1), 0::size(1),
               1::size(1)>>
             |> Flags.from_binary()

    assert {:ok,
            %Flags{
              ed: false,
              at: false,
              bs: false,
              be: false,
              uv: false,
              up: false,
              flags: <<0>>
            }} ==
             <<0::size(1), 0::size(1), 0::size(1), 0::size(1), 0::size(1), 0::size(1), 0::size(1),
               0::size(1)>>
             |> Flags.from_binary()
  end
end
