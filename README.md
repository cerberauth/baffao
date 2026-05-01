# Baffao

Baffao is a Rust implementation of OAuth 2.0 for Browser-Based Applications, specifically implementing the Backend For Frontend (BFF) and Token-Mediating Backend patterns as defined in the [OAuth 2.0 for Browser-Based Apps specification](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-browser-based-apps).

## Features

- Unified API supporting both architectural patterns:
  - **Backend For Frontend (BFF)** pattern implementation, which handles all OAuth responsibilities and API proxying
  - **Token-Mediating Backend** pattern implementation, which manages tokens but allows direct resource server access
- Enhanced security features:
  - Token binding with DPoP (Demonstrating Proof of Possession)
  - Robust PKCE challenge verification
  - OAuth state parameter validation
  - Advanced CSRF protection
  - Authorization server validation
  - Token scope validation and least privilege enforcement
  - Rate limiting for token requests
  - Token revocation
  - JWK validation for token verification
  - Secure proxy request validation
- WebAssembly (WASM) support for deployment in JavaScript applications or edge workers
- Ready-to-deploy HTTP Server with flexible configuration

## Project Structure

- **baffao-core**: Core OAuth 2.0 implementation, security features, and shared functionality
- **baffao-backend**: Unified implementation of both BFF and TMI patterns with pattern selection
- **baffao-server**: HTTP server with ready-to-deploy configuration
- **baffao-wasm**: WebAssembly bindings and integration

## Getting Started

### Prerequisites

- Rust 1.70.0 or later
- For WASM compilation: wasm-pack

### Installation

```bash
# Clone the repository
git clone https://github.com/your-username/baffao.git
cd baffao

# Build the project
cargo build --release

# Run the server
cargo run --bin baffao-server
```

### Using as a Library

Add the following to your `Cargo.toml`:

```toml
[dependencies]
baffao-core = "0.1.0"  # If you need only core functionality
baffao-backend = "0.1.0"  # For both BFF and TMI patterns
```

### Choosing a Pattern

When using the backend library, you can choose which pattern to use:

```rust
use baffao_backend::{BackendBuilder, BackendConfig, BackendType};

// For BFF pattern
let config = BackendConfig {
    backend_type: BackendType::BFF,
    // ... other config options
};

// For TMI pattern
let config = BackendConfig {
    backend_type: BackendType::TMI,
    // ... other config options
};

// Build the backend
let backend = BackendBuilder::new(config)
    .with_session_manager(session_manager)
    .with_token_manager(token_manager)
    .build()
    .expect("Failed to build backend");

// Create the router
let app = baffao_backend::create_router(backend);
```

### WebAssembly Usage

```bash
# Build WebAssembly package
cd baffao-wasm
wasm-pack build --target web
```

## Security Best Practices

Baffao implements the following security best practices:

1. **Secure Token Handling**: Tokens are never exposed to the browser in BFF mode and are properly managed in TMI mode.

2. **PKCE Implementation**: Proper implementation of PKCE (RFC 7636) to secure the authorization code flow.

3. **Token Binding**: Support for DPoP (RFC 9449) to bind tokens to specific clients.

4. **CSRF Protection**: Advanced CSRF protection with token validation.

5. **Authorization Server Validation**: Validates the issuer and endpoints of the authorization server.

6. **Token Scope Validation**: Implements least privilege by validating token scopes.

7. **Rate Limiting**: Protects against abuse with configurable rate limiting.

8. **Token Revocation**: Proper implementation of RFC 7009 for token revocation.

9. **Secure Proxying**: Request validation, sanitization, and security headers for proxied requests.

10. **JWK Validation**: Validates tokens against JWK sets from the authorization server.

## Examples

See the `/examples` directory for implementation examples.

## License

Licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

## Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you shall be dual licensed as above, without any additional terms or conditions.
