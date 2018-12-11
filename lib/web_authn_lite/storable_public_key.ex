defmodule WebAuthnLite.StorablePublicKey do
  @moduledoc """
  This module defines a public key structure that Relying party can store.

  * credential_id
  * public_key
  * sign_count
  """

  defstruct [:credential_id, :public_key, :sign_count]

  @type t :: %__MODULE__{
          credential_id: String.t(),
          public_key:
            WebAuthnLite.CredentialPublicKey.RS256.t()
            | WebAuthnLite.CredentialPublicKey.ES256.t(),
          sign_count: integer
        }
end
