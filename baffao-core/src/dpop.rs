//! DPoP (Demonstrating Proof-of-Possession) implementation.
//!
//! This module provides functionality for implementing DPoP (RFC 9449),
//! which binds tokens to a specific client key pair.

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use hmac::{Hmac, Mac};
use jwt::{AlgorithmType, Header, SignWithKey, Token, VerifyWithKey};
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use url::Url;

use crate::error::{BaffaoError, BaffaoResult};
use crate::token::{AccessToken, RefreshToken};

/// Represents a DPoP key pair
#[derive(Clone)]
pub struct DPoPKeyPair {
    /// The public key as a JWK
    jwk: Arc<jsonwebtoken::jwk::Jwk>,
    /// The thumbprint of the JWK
    thumbprint: String,
}

/// Represents the claims in a DPoP proof
#[derive(Debug, Serialize, Deserialize)]
struct DPoPProofClaims {
    /// JWT ID (unique identifier for the proof)
    jti: String,
    /// HTTP method of the request
    htm: String,
    /// HTTP URI of the request (without query parameters)
    htu: String,
    /// Issued at timestamp
    iat: u64,
    /// Expiration timestamp (optional)
    #[serde(skip_serializing_if = "Option::is_none")]
    exp: Option<u64>,
    /// Nonce provided by the server (optional)
    #[serde(skip_serializing_if = "Option::is_none")]
    nonce: Option<String>,
    /// Typ of the token (must be "dpop+jwt")
    typ: String,
}

/// JWK representation for DPoP proofs
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwkRepresentation {
    /// Key type (e.g., "EC", "RSA")
    pub kty: String,
    /// Curve for EC keys (e.g., "P-256")
    #[serde(skip_serializing_if = "Option::is_none")]
    pub crv: Option<String>,
    /// x coordinate for EC keys
    #[serde(skip_serializing_if = "Option::is_none")]
    pub x: Option<String>,
    /// y coordinate for EC keys
    #[serde(skip_serializing_if = "Option::is_none")]
    pub y: Option<String>,
    /// Modulus for RSA keys
    #[serde(skip_serializing_if = "Option::is_none")]
    pub n: Option<String>,
    /// Exponent for RSA keys
    #[serde(skip_serializing_if = "Option::is_none")]
    pub e: Option<String>,
}

impl DPoPKeyPair {
    /// Creates a new DPoP key pair using a P-256 EC key
    pub fn new_p256() -> BaffaoResult<Self> {
        let thumbprint = String::new(); // Placeholder
        
        let jwk = jsonwebtoken::jwk::Jwk {
            common: jsonwebtoken::jwk::CommonParameters {
                key_id: Some(thumbprint.clone()),
                public_key_use: Some(jsonwebtoken::jwk::PublicKeyUse::Signature),
                ..Default::default()
            },
            algorithm: jsonwebtoken::jwk::AlgorithmParameters::EllipticCurve(
                jsonwebtoken::jwk::EllipticCurveKeyParameters {
                    key_type: jsonwebtoken::jwk::EllipticCurveKeyType::EC,
                    curve: jsonwebtoken::jwk::EllipticCurve::P256,
                    x: String::new(), // This will be set by the actual key generation
                    y: String::new(),
                }
            ),
        };
        
        Ok(Self {
            jwk: Arc::new(jwk),
            thumbprint,
        })
    }

    /// Returns the public key as a JWK
    pub fn jwk(&self) -> &jsonwebtoken::jwk::Jwk {
        &self.jwk
    }

    /// Returns the JWK thumbprint
    pub fn thumbprint(&self) -> &str {
        &self.thumbprint
    }

    /// Returns the JWK as a JSON string
    pub fn jwk_json(&self) -> BaffaoResult<String> {
        serde_json::to_string(&*self.jwk)
            .map_err(|e| BaffaoError::Serialization(format!("Failed to serialize JWK: {}", e)))
    }

    /// Converts the JWK to a representation suitable for DPoP proofs
    pub fn to_jwk_representation(&self) -> BaffaoResult<JwkRepresentation> {
        match &self.jwk.algorithm {
            jsonwebtoken::jwk::AlgorithmParameters::EllipticCurve(ec_params) => {
                let x = Some(ec_params.x.clone());
                let y = Some(ec_params.y.clone());
                let crv = format!("{:?}", ec_params.curve);

                Ok(JwkRepresentation {
                    kty: "EC".to_string(),
                    crv: Some(crv),
                    x,
                    y,
                    n: None,
                    e: None,
                })
            }
            jsonwebtoken::jwk::AlgorithmParameters::RSA(rsa_params) => {
                let n = Some(rsa_params.n.clone());
                let e = Some(rsa_params.e.clone());

                Ok(JwkRepresentation {
                    kty: "RSA".to_string(),
                    crv: None,
                    x: None,
                    y: None,
                    n,
                    e,
                })
            }
            _ => Err(BaffaoError::InvalidDpopProof(
                "Unsupported key type".to_string(),
            )),
        }
    }

    /// Creates a DPoP proof for the given request parameters
    pub fn create_proof(
        &self,
        method: &str,
        url: &Url,
        nonce: Option<&str>,
    ) -> BaffaoResult<String> {
        let mut jti_bytes = [0u8; 16];
        OsRng.fill_bytes(&mut jti_bytes);
        let jti = URL_SAFE_NO_PAD.encode(jti_bytes);

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // 1 minute expiration
        let exp = Some(now + 60);

        // Create claims
        let claims = DPoPProofClaims {
            typ: "dpop+jwt".to_string(),
            jti,
            htm: method.to_uppercase(),
            htu: url.to_string(),
            iat: now,
            exp,
            nonce: nonce.map(|s| s.to_string()),
        };

        // Create JWT header
        let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::ES256);
        header.typ = Some("dpop+jwt".to_string());
        header.jwk = Some((*self.jwk).clone());

        // Create the signing key
        let signing_key = jsonwebtoken::EncodingKey::from_ec_der(&[0u8; 32]); // Placeholder


        // Sign the JWT
        let token = jsonwebtoken::encode(
            &header,
            &claims,
            &signing_key,
        )
        .map_err(|e| BaffaoError::CryptoError(format!("Failed to sign DPoP proof: {}", e)))?;

        Ok(token)
    }

    /// Verifies a DPoP proof
    pub fn verify_proof(
        &self,
        proof: &str,
        method: &str,
        url: &Url,
        expected_nonce: Option<&str>,
    ) -> BaffaoResult<String> {
        // Parse the JWT header to get the JWK and algorithm
        let header_json = jsonwebtoken::decode_header(proof)
            .map_err(|e| BaffaoError::InvalidDpopProof(format!("Invalid proof header: {}", e)))?;

        let alg = match header_json.alg {
            jsonwebtoken::Algorithm::ES256 => "ES256",
            jsonwebtoken::Algorithm::RS256 => "RS256",
            _ => return Err(BaffaoError::InvalidDpopProof("Unsupported algorithm".to_string())),
        };

        // Get the JWK from the header
        let header: serde_json::Value = serde_json::from_str(
            &serde_json::to_string(&header_json).unwrap_or_default()
        ).unwrap_or(serde_json::Value::Null);

        // Extract the JWK
        let jwk = header["jwk"].clone();
        if jwk.is_null() {
            return Err(BaffaoError::InvalidDpopProof("Missing jwk header".to_string()));
        }

        // Parse the JWK
        let jwk: jsonwebtoken::jwk::Jwk = serde_json::from_value(jwk)
            .map_err(|e| BaffaoError::InvalidDpopProof(format!("Invalid JWK: {}", e)))?;

        // Create verification key based on the JWK
        let verification_key = jsonwebtoken::DecodingKey::from_jwk(&jwk)
            .map_err(|e| BaffaoError::CryptoError(format!("Failed to create verification key: {}", e)))?;

        // Set validation parameters
        let mut validation = jsonwebtoken::Validation::new(
            if alg == "ES256" {
                jsonwebtoken::Algorithm::ES256
            } else {
                jsonwebtoken::Algorithm::RS256
            }
        );
        validation.set_required_spec_claims(&["htm", "htu", "iat", "jti"]);
        validation.validate_exp = true;

        // Decode and verify the proof
        let token_data = jsonwebtoken::decode::<DPoPProofClaims>(proof, &verification_key, &validation)
            .map_err(|e| BaffaoError::InvalidDpopProof(format!("Invalid proof: {}", e)))?;

        let claims = token_data.claims;

        // Verify HTTP method and URI
        if claims.htm != method.to_uppercase() {
            return Err(BaffaoError::InvalidDpopProof(format!(
                "Method mismatch: expected {}, got {}",
                method.to_uppercase(),
                claims.htm
            )));
        }

        if claims.htu != url.to_string() {
            return Err(BaffaoError::InvalidDpopProof(format!(
                "URI mismatch: expected {}, got {}",
                url, claims.htu
            )));
        }

        // Verify nonce if expected
        if let Some(expected) = expected_nonce {
            match claims.nonce {
                Some(ref nonce) if nonce == expected => {}
                _ => return Err(BaffaoError::InvalidDpopProof("Nonce mismatch or missing".to_string())),
            }
        }

        // Generate JWK thumbprint (placeholder)
        let thumbprint = String::new();
        
        Ok(thumbprint)
    }
}

/// DPoP proof verifier that can keep track of nonces
pub struct DPoPVerifier {
    nonces: tokio::sync::Mutex<std::collections::HashMap<String, u64>>,
}

impl DPoPVerifier {
    /// Creates a new DPoP verifier
    pub fn new() -> Self {
        Self {
            nonces: tokio::sync::Mutex::new(std::collections::HashMap::new()),
        }
    }

    /// Generates a new nonce
    pub async fn generate_nonce(&self) -> String {
        let mut nonce_bytes = [0u8; 16];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = URL_SAFE_NO_PAD.encode(nonce_bytes);

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let mut nonces = self.nonces.lock().await;
        nonces.insert(nonce.clone(), now);

        // Cleanup old nonces
        nonces.retain(|_, &mut timestamp| now - timestamp < 3600);

        nonce
    }

    /// Verifies a nonce
    pub async fn verify_nonce(&self, nonce: &str) -> bool {
        let mut nonces = self.nonces.lock().await;
        nonces.remove(nonce).is_some()
    }
}

/// Extension trait for OAuth 2.0 clients to support DPoP
#[async_trait]
pub trait DPoPClientExt {
    /// Exchanges an authorization code for tokens using DPoP
    async fn exchange_code_dpop(
        &self,
        code: String,
        pkce_verifier: String,
        key_pair: &DPoPKeyPair,
    ) -> BaffaoResult<oauth2::basic::BasicTokenResponse>;

    /// Refreshes an access token using DPoP
    async fn refresh_token_dpop(
        &self,
        refresh_token: &str,
        key_pair: &DPoPKeyPair,
    ) -> BaffaoResult<oauth2::basic::BasicTokenResponse>;
}

mod extensions {
    use super::*;
    use oauth2::basic::BasicTokenResponse;
    use oauth2::{AccessToken, AuthUrl, TokenResponse, TokenUrl};
    use oauth2::{ClientId, ClientSecret, RedirectUrl, RefreshToken};

    #[async_trait]
    impl DPoPClientExt for crate::auth::OAuthClient {
        async fn exchange_code_dpop(
            &self,
            code: String,
            code_verifier: String,
            key_pair: &DPoPKeyPair,
        ) -> BaffaoResult<BasicTokenResponse> {
            let token_url = self.get_token_url()?;
            let redirect_url = self.get_redirect_url()?;
            let client_id = self.get_client_id();

            let client = reqwest::Client::new();
            let mut params = vec![
                ("grant_type", "authorization_code"),
                ("code", &code),
                ("redirect_uri", &redirect_url),
                ("code_verifier", &code_verifier),
                ("client_id", &client_id),
            ];

            let secret = self.get_client_secret();
            if let Some(ref s) = secret {
                params.push(("client_secret", s));
            }

            let proof = key_pair.create_proof("POST", &token_url.url(), None)?;

            let response = client
                .post(token_url.as_str())
                .header("DPoP", proof)
                .form(&params)
                .send()
                .await
                .map_err(|e| BaffaoError::Network(format!("Failed to send request: {}", e)))?;

            if !response.status().is_success() {
                let status = response.status();
                let error_text = response.text().await.unwrap_or_default();
                return Err(BaffaoError::OAuthExchange(format!(
                    "Token request failed ({}): {}",
                    status, error_text
                )));
            }

            #[derive(Deserialize)]
            struct TokenResponseJson {
                access_token: String,
                token_type: String,
                expires_in: Option<u64>,
                refresh_token: Option<String>,
                scope: Option<String>,
            }

            let token_response: TokenResponseJson = response.json().await.map_err(|e| {
                BaffaoError::Serialization(format!("Failed to parse token response: {}", e))
            })?;

            if token_response.token_type.to_lowercase() != "dpop" {
                return Err(BaffaoError::TokenValidation(format!(
                    "Invalid token type: expected DPoP, got {}",
                    token_response.token_type
                )));
            }

            // Create the OAuth token response
            let mut result = BasicTokenResponse::new(
                AccessToken::new(token_response.access_token),
                oauth2::basic::BasicTokenType::Bearer,
                oauth2::EmptyExtraTokenFields {},
            );

            if let Some(expires_in) = token_response.expires_in {
                let duration = Duration::from_secs(expires_in);
                result.set_expires_in(Some(&duration));
            }

            // Add refresh token if available
            if let Some(refresh_token) = token_response.refresh_token {
                result.set_refresh_token(Some(RefreshToken::new(refresh_token)));
            }

            // Add scope if available
            if let Some(scope) = token_response.scope {
                let scopes: Vec<oauth2::Scope> = scope
                    .split(' ')
                    .map(|s| oauth2::Scope::new(s.to_string()))
                    .collect();
                result.set_scopes(Some(scopes));
            }

            Ok(result)
        }

        async fn refresh_token_dpop(
            &self,
            refresh_token: &str,
            key_pair: &DPoPKeyPair,
        ) -> BaffaoResult<BasicTokenResponse> {
            let token_url = self.get_token_url()?;
            let client_id = self.get_client_id();

            let client = reqwest::Client::new();
            let mut params = vec![
                ("grant_type", "refresh_token"),
                ("refresh_token", refresh_token),
                ("client_id", &client_id),
            ];

            let secret = self.get_client_secret();
            if let Some(ref s) = secret {
                params.push(("client_secret", s));
            }

            let proof = key_pair.create_proof("POST", &token_url.url(), None)?;

            let response = client
                .post(token_url.as_str())
                .header("DPoP", proof)
                .form(&params)
                .send()
                .await
                .map_err(|e| BaffaoError::Network(format!("Failed to send request: {}", e)))?;

            if !response.status().is_success() {
                let status = response.status();
                let error_text = response.text().await.unwrap_or_default();
                return Err(BaffaoError::OAuthRefresh(format!(
                    "Token refresh failed ({}): {}",
                    status, error_text
                )));
            }

            #[derive(Deserialize)]
            struct TokenResponseJson {
                access_token: String,
                token_type: String,
                expires_in: Option<u64>,
                refresh_token: Option<String>,
                scope: Option<String>,
            }

            let token_response: TokenResponseJson = response.json().await.map_err(|e| {
                BaffaoError::Serialization(format!("Failed to parse token response: {}", e))
            })?;

            if token_response.token_type.to_lowercase() != "dpop" {
                return Err(BaffaoError::TokenValidation(format!(
                    "Invalid token type: expected DPoP, got {}",
                    token_response.token_type
                )));
            }

            // Create the OAuth token response
            let mut result = BasicTokenResponse::new(
                AccessToken::new(token_response.access_token),
                oauth2::basic::BasicTokenType::Bearer,
                oauth2::EmptyExtraTokenFields {},
            );

            if let Some(expires_in) = token_response.expires_in {
                let duration = Duration::from_secs(expires_in);
                result.set_expires_in(Some(&duration));
            }

            // Add refresh token if available
            if let Some(refresh_token) = token_response.refresh_token {
                result.set_refresh_token(Some(RefreshToken::new(refresh_token)));
            }

            // Add scope if available
            if let Some(scope) = token_response.scope {
                let scopes: Vec<oauth2::Scope> = scope
                    .split(' ')
                    .map(|s| oauth2::Scope::new(s.to_string()))
                    .collect();
                result.set_scopes(Some(scopes));
            }

            Ok(result)
        }
    }

    impl crate::auth::OAuthClient {
        /// Gets the token URL
        fn get_token_url(&self) -> BaffaoResult<&TokenUrl> {
            self.client().token_url().ok_or_else(|| BaffaoError::Configuration("Token URL not configured".to_string()))
        }

        /// Gets the redirect URL
        fn get_redirect_url(&self) -> BaffaoResult<String> {
            Ok(self.client().redirect_url().unwrap().url().to_string())
        }

        /// Gets the client ID
        fn get_client_id(&self) -> String {
            self.client().client_id().as_str().to_string()
        }

        /// Gets the client secret
        fn get_client_secret(&self) -> Option<String> {
            self.client_secret().cloned()
        }
    }
}
