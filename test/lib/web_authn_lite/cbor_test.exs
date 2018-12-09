defmodule WebAuthnLite.CBORTest do
  use ExUnit.Case, async: false
  alias WebAuthnLite.CBOR

  test "unsigned int" do
    assert CBOR.decode(<<0>>) == {:ok, 0}
    assert CBOR.decode(<<23>>) == {:ok, 23}
    assert CBOR.decode(<<24, 24>>) == {:ok, 24}
    assert CBOR.decode(<<24, 255>>) == {:ok, 255}
    assert CBOR.decode(<<25, 1, 0>>) == {:ok, 256}
    assert CBOR.decode(<<25, 255, 255>>) == {:ok, 65535}
    assert CBOR.decode(<<26, 0, 1, 0, 0>>) == {:ok, 65536}
    assert CBOR.decode(<<26, 255, 255, 255, 255>>) == {:ok, 4_294_967_295}
    assert CBOR.decode(<<27, 0, 0, 0, 1, 0, 0, 0, 0>>) == {:ok, 4_294_967_296}

    assert CBOR.decode(<<27, 255, 255, 255, 255, 255, 255, 255, 255>>) ==
             {:ok, 18_446_744_073_709_551_615}
  end

  test "negative int" do
    assert CBOR.decode(<<32>>) == {:ok, -1}
    assert CBOR.decode(<<55>>) == {:ok, -24}
    assert CBOR.decode(<<56, 24>>) == {:ok, -25}
    assert CBOR.decode(<<56, 255>>) == {:ok, -256}
    assert CBOR.decode(<<57, 1, 0>>) == {:ok, -257}
    assert CBOR.decode(<<57, 255, 255>>) == {:ok, -65536}
    assert CBOR.decode(<<58, 0, 1, 0, 0>>) == {:ok, -65537}
    assert CBOR.decode(<<58, 255, 255, 255, 255>>) == {:ok, -4_294_967_296}
    assert CBOR.decode(<<59, 0, 0, 0, 1, 0, 0, 0, 0>>) == {:ok, -4_294_967_297}

    assert CBOR.decode(<<59, 255, 255, 255, 255, 255, 255, 255, 255>>) ==
             {:ok, -18_446_744_073_709_551_616}
  end

  test "text" do
    assert CBOR.decode(<<96>>) == {:ok, ""}
    assert CBOR.decode(<<97, 97>>) == {:ok, "a"}
    assert CBOR.decode(<<100, 73, 69, 84, 70>>) == {:ok, "IETF"}
    assert CBOR.decode(<<98, 34, 92>>) == {:ok, "\"\\"}
    assert CBOR.decode(<<98, 195, 188>>) == {:ok, "\u00fc"}
    assert CBOR.decode(<<99, 230, 176, 180>>) == {:ok, "\u6c34"}
  end

  test "bytes" do
    assert CBOR.decode(<<64>>) == {:ok, ""}
    assert CBOR.decode(<<68, 1, 2, 3, 4>>) == {:ok, "01020304" |> Base.decode16!()}
  end

  test "array" do
    assert CBOR.decode(<<128>>) == {:ok, []}
    assert CBOR.decode(<<131, 1, 2, 3>>) == {:ok, [1, 2, 3]}
    assert CBOR.decode(<<131, 1, 130, 2, 3, 130, 4, 5>>) == {:ok, [1, [2, 3], [4, 5]]}

    assert CBOR.decode(
             <<152, 25, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21,
               22, 23, 24, 24, 24, 25>>
           ) ==
             {:ok,
              [
                1,
                2,
                3,
                4,
                5,
                6,
                7,
                8,
                9,
                10,
                11,
                12,
                13,
                14,
                15,
                16,
                17,
                18,
                19,
                20,
                21,
                22,
                23,
                24,
                25
              ]}
  end

  test "map" do
    assert CBOR.decode(<<160>>) == {:ok, %{}}
    assert CBOR.decode(<<162, 1, 2, 3, 4>>) == {:ok, %{1 => 2, 3 => 4}}

    assert CBOR.decode(
             <<165, 97, 97, 97, 65, 97, 98, 97, 66, 97, 99, 97, 67, 97, 100, 97, 68, 97, 101, 97,
               69>>
           ) == {:ok, %{"a" => "A", "b" => "B", "c" => "C", "d" => "D", "e" => "E"}}
  end

  test "mixed" do
    assert CBOR.decode(<<162, 97, 97, 1, 97, 98, 130, 2, 3>>) == {:ok, %{"a" => 1, "b" => [2, 3]}}
    assert CBOR.decode(<<130, 97, 97, 161, 97, 98, 97, 99>>) == {:ok, ["a", %{"b" => "c"}]}
  end
end
