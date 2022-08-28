use serde::{Deserialize, Serialize};

pub trait Authenticator {
    fn authenticate(&self, user: &str, pass: &str) -> bool;
}

impl<T: Authenticator> Authenticator for &T {
    fn authenticate(&self, user: &str, pass: &str) -> bool {
        T::authenticate(self, user, pass)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Authentication {
    NoAuth,
    Basic(String, String),
}

impl Authenticator for Authentication {
    fn authenticate(&self, user: &str, pass: &str) -> bool {
        match self {
            Authentication::NoAuth => true,
            Authentication::Basic(u, p) => u == user && p == pass,
        }
    }
}
