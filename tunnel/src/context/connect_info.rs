use tokio::task::JoinHandle;

use crate::context::proxy_type::ProxyType;

pub struct ConnectInfo {
    source_addr: String,
    target_addr: Option<String>,
    connect_type: Option<String>,
    proxy_type: Option<ProxyType>,
    client_job: JoinHandle<()>,
}

impl ConnectInfo {
    pub fn create(source_addr: String, job: JoinHandle<()>) -> Self {
        ConnectInfo {
            source_addr,
            target_addr: None,
            connect_type: None,
            proxy_type: None,
            client_job: job,
        }
    }

    pub fn compare(&self, source_addr: &String) -> bool {
        self.source_addr.eq(source_addr)
    }

    pub fn close(&self) {
        self.client_job.abort();
    }
}
