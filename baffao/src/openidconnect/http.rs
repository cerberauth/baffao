use anyhow::{Error, Ok};
use axum_extra::extract::CookieJar;
use chrono::{Duration, Utc};

use super::OAuthConfig;
use crate::cookies::new_cookie;
use crate::session::{update_session, Session};
use crate::{openidconnect::OAuthClient, settings::CookiesConfig};

#[derive(Clone)]
pub struct OpenIDConnectHttpHandler {
    client: OAuthClient,
    cookies_config: CookiesConfig,
}

impl OpenIDConnectHttpHandler {
    pub fn new(oauth_config: OAuthConfig, cookies_config: CookiesConfig) -> Result<Self, Error> {
        let client = OAuthClient::new(oauth_config)?;

        Ok(Self {
            client,
            cookies_config,
        })
    }

    fn get_access_token(&self, jar: &CookieJar) -> Result<Option<String>, Error> {
        let access_token = jar
            .get(self.cookies_config.access_token.name.as_str())
            .map(|cookie| cookie.value().to_string());
        Ok(access_token)
    }

    fn get_refresh_token(&self, jar: &CookieJar) -> Result<Option<String>, Error> {
        let access_token = jar
            .get(self.cookies_config.refresh_token.name.as_str())
            .map(|cookie| cookie.value().to_string());
        Ok(access_token)
    }

    pub fn client(&self) -> &OAuthClient {
        &self.client
    }

    pub async fn get_or_refresh_token(
        &self,
        jar: CookieJar,
    ) -> Result<(CookieJar, Option<String>), Error> {
        let access_token = self.get_access_token(&jar)?;
        if access_token.is_none() {
            return Ok((jar, None));
        }

        self.refresh_access_token(jar).await
    }

    pub async fn refresh_access_token(
        &self,
        jar: CookieJar,
    ) -> Result<(CookieJar, Option<String>), Error> {
        let refresh_token = self.get_refresh_token(&jar)?;
        if refresh_token.is_none() {
            return Ok((jar, None));
        }

        let token_result = self.client.refresh_token(refresh_token.unwrap()).await?;
        let token = token_result.access_token();
        let updated_jar = jar.add(new_cookie(
            self.cookies_config.access_token.to_owned(),
            token.secret().to_string(),
        ));
        Ok((updated_jar, Some(token.secret().to_string())))
    }

    pub fn authorize(&self, jar: CookieJar, scope: Option<Vec<String>>) -> (CookieJar, String) {
        let (url, csrf_token, pkce_code_verifier) = self.client.build_authorization_endpoint(scope);
        let updated_jar = jar
            .add(new_cookie(
                self.cookies_config.oauth_csrf.to_owned(),
                csrf_token.secret().to_string(),
            ))
            .add(new_cookie(
                self.cookies_config.oauth_pkce.to_owned(),
                pkce_code_verifier.secret().to_string(),
            ));
        (updated_jar, url.to_string())
    }

    pub async fn exchange_code(
        &self,
        jar: CookieJar,
        code: String,
        pkce_verifier: String,
    ) -> Result<CookieJar, Error> {
        let token_result = self.client.exchange_code(code, pkce_verifier).await?;
        let token = token_result.access_token();

        let mut updated_jar = jar.add(new_cookie(
            self.cookies_config.access_token.to_owned(),
            token.secret().to_string(),
        ));
        if token_result.refresh_token().is_some() {
            updated_jar = updated_jar.add(new_cookie(
                self.cookies_config.refresh_token.to_owned(),
                token_result.refresh_token().unwrap().secret().to_string(),
            ));
        } else {
            updated_jar = updated_jar.remove(self.cookies_config.refresh_token.to_owned().name);
        }

        if token_result.id_token().is_some() {
            updated_jar = updated_jar.add(new_cookie(
                self.cookies_config.id_token.to_owned(),
                token_result.id_token().unwrap().secret().to_string(),
            ));
        } else {
            updated_jar = updated_jar.remove(self.cookies_config.id_token.to_owned().name);
        }

        let now = Utc::now();
        let expires_in = token_result.expires_in().map(|duration| {
            now.checked_add_signed(Duration::from_std(duration).unwrap())
                .unwrap()
        });
        let session = Session::new(None, Some(now), expires_in);
        updated_jar = update_session(
            updated_jar,
            self.cookies_config.session.to_owned(),
            Some(session),
        );

        Ok(updated_jar)
    }

    pub fn clone(&self) -> Self {
        Self {
            client: self.client.clone(),
            cookies_config: self.cookies_config.clone(),
        }
    }
}
