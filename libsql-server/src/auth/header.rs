#[derive(Debug)]
pub enum HttpAuthHeader {
    Basic(String),
    Bearer(String),
}
