defmodule WebAuthnLite.AttestedCredentialDataTest do
  use ExUnit.Case, async: false

  alias WebAuthnLite.AttestedCredentialData
  doctest AttestedCredentialData

  @encoded_attested_credential_data "-KAR84wKTRWABhcRH57cfQAQMgFGjKKG-M1k5HbJ-Ms-G6UBAgMmIAEhWCAhdQzioFejH76HtfAutOU3ig-P7xsTbvCNeURkhEcviSJYIEWWWqllIYZFROBstONHn8fihSvRIkibegTrn2bmxXFT"

  test "from_binary" do
    assert {:ok, attested_credential_data} =
             @encoded_attested_credential_data |> Base.url_decode64!(padding: false)
             |> AttestedCredentialData.from_binary()

    assert attested_credential_data.aaguid == "-KAR84wKTRWABhcRH57cfQ"
    assert attested_credential_data.credential_id == "MgFGjKKG-M1k5HbJ-Ms-Gw"
    refute is_nil(attested_credential_data.credential_public_key)

    assert attested_credential_data.raw ==
             @encoded_attested_credential_data |> Base.url_decode64!(padding: false)
  end
end
