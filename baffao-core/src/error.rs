pub fn build_error_redirect_url(error_url: &str, message: &str) -> String {
    format!("{}?&message={}", error_url, message)
}
