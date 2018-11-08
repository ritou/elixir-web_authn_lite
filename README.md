# WebAuthnLite

W3C Web Authentication API (a.k.a. WebAuthN / FIDO 2.0) RP library in Elixir

## Installation

If [available in Hex](https://hex.pm/docs/publish), the package can be installed
by adding `web_authn_lite` to your list of dependencies in `mix.exs`:

```elixir
def deps do
  [
    {:web_authn_lite, "~> 0.1.0"}
  ]
end
```

Documentation can be generated with [ExDoc](https://github.com/elixir-lang/ex_doc)
and published on [HexDocs](https://hexdocs.pm). Once published, the docs can
be found at [https://hexdocs.pm/web_authn_lite](https://hexdocs.pm/web_authn_lite).

# Usage : WebAuthn without Attestation

If the RelyingParty does not request Attestation, the implementation of WebAuthn is quite simple.

See https://www.w3.org/TR/webauthn/#attestation-convey

## 1.1. [`Registration`] Generate and store challenge

### Server-side

challenge = WebAuthnLite.Challenge.generate_base64_url_encoded_challenge()

conn
|> put_session(:webauthn_challenge, challenge) # for phenix etc...
...

## 1.2. Request WebAuthn registration

### Client-side

Set Base64 URL decoded challenge, `attestation: "none"` to `CredentialCreationOptions` and call `navigator.credentials.create()`

## 1.3. Send encoded response to Server-side

### Client-side

Encode following params and send them to server-side.

* `PublicKeyCredential.rawId`
* `PublicKeyCredential.response.ClientDataJSON`

## 1.4. Validate ClientDataJSON

### Server-side

challenge = conn |> get_session(:webauthn_challenge)

{:ok, _} = WebAuthnLite.ClientDataJSON.validate(encoded_client_data_json, type, origin, challenge)

## 1.5. Store Credential.Id with account

Registration Success.

## 2.1. [`Authentication`] Generate and store challenge

### Server-side

challenge = WebAuthnLite.Challenge.generate_base64_url_encoded_challenge()

conn
|> put_session(:webauthn_challenge, challenge) # for phenix etc...
...

## 2.2. Request WebAuthn authentication

### Client-side

Set Base64 URL decoded challenge and call `navigator.credentials.get()`

## 2.3. Send encoded response to Server-side

### Client-side

Encode following params and send them to server-side.

* `Id` or `rawId`
* `AuthenticatorAssertionResponse.clientDataJSON`
* `AuthenticatorAssertionResponse.authenticatorData`

## 2.4. Validate clientDataJSON

### Server-side

challenge = conn |> get_session(:webauthn_challenge)

{:ok, _} = WebAuthnLite.ClientDataJSON.validate(encoded_client_data_json, type, origin, challenge)

## 2.5. Validate authenticatorData

Decode and validate authenticatorData.

authenticator_data = WebAuthnLite.AuthenticatorData.decode(encoded_authenticator_data)

* `authenticator_data.rp_id_hash`
* `authenticator_data.flags`
* `authenticator_data.sign_count`

## 2.6 Authentication Success

Authentication Success