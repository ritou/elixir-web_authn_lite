defmodule WebAuthnLite.UserHandleTest do
  use ExUnit.Case, async: false

  alias WebAuthnLite.UserHandle
  doctest UserHandle

  test "decode" do
    assert {:ok, "2134817348"} == UserHandle.decode("MjEzNDgxNzM0OA")
    assert {:error, :invalid_format} == UserHandle.decode(1)
  end
end
