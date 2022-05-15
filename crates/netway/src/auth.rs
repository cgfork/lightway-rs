#[derive(Debug, Clone)]
pub enum Authentication {
    NoAuth,
    Password { username: String, password: String },
}
