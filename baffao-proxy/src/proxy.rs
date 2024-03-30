use axum::{
    extract::{Request, State},
    http::{StatusCode, Uri},
    response::IntoResponse,
};
use axum_extra::extract::CookieJar;
use baffao::{handlers::proxy, oauth::OAuthHttpHandler};

use crate::settings::Settings;
use crate::state::HttpClient;

pub async fn handler(
    jar: CookieJar,
    State(client): State<HttpClient>,
    State(handler): State<OAuthHttpHandler>,
    State(settings): State<Settings>,
    mut req: Request,
) -> impl IntoResponse {
    if settings.proxy.is_none() {
        return (jar, StatusCode::BAD_GATEWAY.into_response());
    }
    let proxy_settings = settings.proxy.as_ref().unwrap();

    let path = req.uri().path();
    let path_query = req
        .uri()
        .path_and_query()
        .map(|v| v.as_str())
        .unwrap_or(path);
    let uri = format!(
        "http://{}:{}{}",
        proxy_settings.host, proxy_settings.port, path_query
    );

    let (updated_jar, headers) = proxy(handler, jar)
        .await
        .map_err(|_| StatusCode::BAD_GATEWAY)
        .unwrap();

    *req.uri_mut() = Uri::try_from(uri).unwrap();
    req.headers_mut().extend(headers);

    (
        updated_jar,
        client
            .request(req)
            .await
            .map_err(|_| StatusCode::BAD_GATEWAY)
            .into_response(),
    )
}
