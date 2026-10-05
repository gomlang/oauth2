# ecosystem::oauth2

OAuth 2.0 client protocol support in GoML, using `ecosystem::request` for HTTP,
`std::net::url` for encoding, and standard cryptographic randomness and SHA-256.
The production library has no custom native implementation.

Supported flows are authorization code with PKCE **S256**, refresh token, and
client credentials. Authentication is explicitly `ClientAuth::Public`,
`ClientAuth::Basic(Secret)`, or `ClientAuth::Post(Secret)`; there is no automatic
fallback between methods. Client credentials requires Basic or Post. Basic
credentials are individually form encoded before Base64 encoding, as required
by OAuth. Post credentials appear in the request body.

```toml
[dependencies]
"ecosystem::oauth2" = "0.1.0"
```

## Authorization code

```goml
use ecosystem::oauth2;
use std::context;

fn configured_client() -> Result[oauth2::Client, oauth2::Error] {
    oauth2::Client::new(
        "registered-client-id",
        "https://auth.example/token",
        oauth2::ClientAuth::Public,
        oauth2::Options {
            expected_issuer: Option::Some("https://auth.example"),
            ..oauth2::Options::new()
        },
    )
}

fn begin(client: oauth2::Client) -> Result[oauth2::Authorization, oauth2::Error] {
    client.authorization(
        "https://auth.example/authorize",
        "https://app.example/callback",
        Vec::from_array(["profile"]),
    )
}

fn finish(flow: oauth2::Authorization, callback_url: string)
    -> Result[oauth2::Token, oauth2::Error] {
    flow.exchange(context::Context::background(), callback_url)
}
```

Keep the configured client alive for its flows and close it during application
shutdown. Redirect the browser to `flow.url()` and retain the flow in the initiating
user's server-side session. Pass the **complete callback URL** to `exchange`.
The scheme, authority and path must match the configured redirect URI exactly;
registered query fields must retain their decoded values. Duplicate query
names, fragments, missing/mismatched state, ambiguous code/error responses and
invalid UTF-8 are rejected before a token request. Extra unique response
parameters are ignored. Endpoint queries cannot override protocol parameters.

Each flow generates independent 32-byte random state and PKCE verifier values.
`Pkce::from_verifier` accepts 43–128 unreserved ASCII characters; `challenge`
computes S256. `Pkce::matches` and state validation use the standard digest
comparison primitive. Plain PKCE is not supported.

Copied `Authorization` handles share one synchronized consumption flag. A valid
state-bound success or OAuth denial consumes the flow once. Invalid callbacks
do not consume it. A code exchange remains consumed after cancellation or a
transport/server error; start a new flow instead of retrying the code. The
library does not store sessions or impose a flow lifetime: applications must
bind a flow to the initiating user, enforce expiration and discard it when done.

`expected_issuer` enables RFC 9207 checking: configure the server's exact HTTPS
issuer URL without query or fragment; both success and error callbacks must
then contain matching `iss`. Without it, `iss` is ignored. Applications using
multiple authorization servers must configure issuer validation or use a
distinct, correctly routed redirect URI for each server to prevent mix-up.
Endpoints and issuer values are trusted application configuration, not user
input. This package does not discover or authenticate an arbitrary provider.

## Token operations

`client.refresh(context, refresh_token, scopes)` and
`client.client_credentials(context, scopes)` make one form-encoded POST.
An empty scopes vector omits `scope`. Scope tokens must be nonempty, unique and
use the OAuth ASCII scope alphabet; requesting a refresh scope broader than the
original grant is the caller's responsibility. Token type, expiry and scope
are returned metadata; there is no automatic bearer injection or token refresh.

`Token` exposes `access_token()`, optional `refresh_token()`, `token_type()`,
optional `expires_in()` in whole seconds and optional `scopes()` (a copy).
Missing expiry/scope differs from zero expiry; a supplied empty scope string is
invalid. Refresh-token rotation, secure storage, expiration accounting and
synchronizing concurrent refreshes belong to the caller. Never overwrite a
stored refresh token merely because the response omitted it.

Responses require HTTP 200 and a JSON object with string `access_token` and
`token_type`. Optional known fields have strict types; `expires_in` is a
nonnegative decimal integer fitting `isize`. Duplicate top-level JSON names are
rejected, including extension names; unknown extension values are ignored
within JSON limits. Token types accept registered-name syntax or an absolute
URI. Opaque credentials/codes/tokens are bounded UTF-8 strings with no ASCII
control characters. Token JSON and error JSON must be UTF-8 `application/json`.
Non-200 OAuth errors become `ErrorKind::Remote`; malformed responses become
`Protocol`. Redirects become `Http` errors and are never followed.

## Transport, limits and secrets

HTTPS with certificate and hostname verification is the default for token,
authorization and redirect URLs. URL credentials and fragments (including an
empty `#`) are rejected. `TransportPolicy::LoopbackHttp` additionally permits
HTTP only with the exact numeric hosts `127.0.0.1` or `[::1]`, for explicit local
integration and callback use. It does not permit `localhost`, other 127/8
addresses or arbitrary HTTP hosts. Custom app URI schemes are not supported.
`Options.root_certificate` adds trusted PEM certificates; there is no option to
disable verification. Environment proxies, cookies, decompression and redirects
are disabled on the private HTTP client.

`Options::new()` uses a 30-second request timeout and 64 KiB request/response
body limits. Body limits must be 1 byte through 16 MiB. Explicit contexts support
cancellation and deadlines; request timeout still applies. Endpoints, opaque
values and the joined scope string are limited to 16 KiB; authorization URLs to
64 KiB. Queries allow at most 128 unique fields; JSON limits include depth 16,
1024 values, 128 entries per container and 32-byte numbers. No retries are
performed by the protocol layer. `Client.close()` closes the shared transport;
copies of the client and retained flows share that lifecycle.

`Secret` requires explicit `.expose()` to obtain its string. Debug output for
Secret, credentials, tokens, clients and authorization handles is redacted.
Errors include a kind, optional HTTP status and a static safe message; remote
error code/description/URI are available as `Option[Secret]`. Raw transport
errors and response bodies are never included. Explicitly exposed values,
authorization URLs and callback URLs remain sensitive and must not be logged.
Redaction is not memory zeroization: immutable string copies may remain in
memory. Returned remote text is untrusted even after explicit exposure.

## Scope and verification

No OIDC/ID-token validation, discovery, dynamic registration, device flow,
implicit/password grants, revocation, introspection, DPoP or mTLS client
authentication is implemented. This package is not an authorization server.

`goml run --example basic` is an offline smoke that generates a flow and prints
only a fixed message and redacted PKCE metadata. `goml test` uses a real local
HTTP/TLS service in `testserver/`; its Go implementation independently parses
form/Basic requests and computes PKCE hashes. Tests cover concurrent flow
consumption, TLS trust, redirects, malformed/error responses, body limits,
cancellation and deadlines. `goml verify` checks the isolated pure-GoML example
consumer. Native oracle checks: `go test ./testserver` and
`go test -race ./testserver`; the GoML tests can also run with `GOFLAGS=-race`.

Protocol references: [RFC 6749](https://www.rfc-editor.org/rfc/rfc6749),
[PKCE / RFC 7636](https://www.rfc-editor.org/rfc/rfc7636),
[OAuth Security BCP / RFC 9700](https://www.rfc-editor.org/rfc/rfc9700), and
[issuer identification / RFC 9207](https://www.rfc-editor.org/rfc/rfc9207).
