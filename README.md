# WebAuthnLite

W3C Web Authentication API (a.k.a. WebAuthN / FIDO 2.0) RP library in Elixir

## Installation

If [available in Hex](https://hex.pm/docs/publish), the package can be installed
by adding `web_authn_lite` to your list of dependencies in `mix.exs`:

```elixir
def deps do
  [
    {:web_authn_lite, "~> 0.3"}
  ]
end
```

Documentation can be generated with [ExDoc](https://github.com/elixir-lang/ex_doc)
and published on [HexDocs](https://hexdocs.pm). Once published, the docs can
be found at [https://hexdocs.pm/web_authn_lite](https://hexdocs.pm/web_authn_lite).

# Usage : 1. Registration

## 1.1. Generate and store challenge

### Server-side

```Elixir
challenge = WebAuthnLite.Challenge.generate_base64_url_encoded_challenge()

conn
|> put_session(:webauthn_register_challenge, challenge) # for phenix etc...
...
```

## 1.2. Request WebAuthn registration

### Client-side

Set Base64 URL decoded challenge and call `navigator.credentials.create()`

## 1.3. Send encoded response to Server-side

### Client-side

Encode following params and send them to server-side.

* `clientDataJSON`
* `attestationObject`

## 1.4. Validate ClientDataJSON

### Server-side

```Elixir
challenge = conn |> get_session(:webauthn_register_challenge)

{:ok, client_data_json} =
  WebAuthnLite.Operation.Register.validate_client_data_json(
    %{client_data_json: encoded_client_data_json,
      origin: origin,
      challenge: challenge
    }
  )
```

## 1.5. Validate AttestationObject

### Server-side

```Elixir
{:ok, storable_public_key, attestation_object} = 
  WebAuthnLite.Operation.Register.validate_attestation_object(
    %{attestation_object: encoded_attestation_object,
      client_data_json: encoded_client_data_json,
      rp_id: rp_id,
      up_required: up_required,
      uv_required: uv_required})
```

## 1.6. Store Credential.Id with account

### Server-side

```Elixir
pubkey = attestation_object.auth_data.attested_credential_data.credential_public_key

# identifier
pubkey_id = attestation_object.auth_data.attested_credential_data.credential_id

# key params
pubkey_map = pubkey.map
pubkey_json = pubkey.json
```

# Usage : 2. Authentication

## 2.1. Generate and store challenge

### Server-side

```Elixir
challenge = WebAuthnLite.Challenge.generate_base64_url_encoded_challenge()

conn
|> put_session(:webauthn_authn_challenge, challenge) # for phenix etc...
...
```

## 2.2. Request WebAuthn authentication

### Client-side

Set Base64 URL decoded challenge and call `navigator.credentials.get()`

## 2.3. Send encoded response to Server-side

### Client-side

Encode following params and send them to server-side.

* `clientDataJSON`
* `authenticatorData`
* `signature`

## 2.4. Validate clientDataJSON

### Server-side

```
challenge = conn |> get_session(:webauthn_authn_challenge)

{:ok, client_data_json} =
  WebAuthnLite.Operation.Authenticate.validate_client_data_json(
    %{client_data_json: encoded_client_data_json,
      origin: origin,
      challenge: challenge
    }
  )
```

## 2.5. Validate authenticatorData

```Elixir
{:ok, updated_storable_public_key, authenticator_data} =
  WebAuthnLite.Operation.Authenticate.validate_authenticator_assertion(
    %{credential_id: credential_id,
      signature: encoded_signature,
      authenticator_data: encoded_authenticator_data,
      client_data_json: encoded_client_data_json,
      public_keys: [storable_public_key],
      rp_id: rp_id,
      up_required: up_required,
      uv_required: uv_required})
```
