#[derive(PartialEq, Clone)]
pub enum ProxyType {
    Redirect,
    Reject,
    Proxy,
}

impl ProxyType {
    pub fn from_index(i: i32) -> Self {
        match i {
            0 => {
                ProxyType::Redirect
            }
            1 => {
                ProxyType::Reject
            }
            2 => {
                ProxyType::Proxy
            }
            _ => {
                ProxyType::Redirect
            }
        }
    }
}