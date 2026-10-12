//! Feature-gated production DNS adapter bridging `leas-dns` to the
//! engine's [`DnsSink`](crate::resolve::DnsSink) seam.

use std::{future::Future, net::IpAddr, pin::Pin, sync::Arc};

use crate::{error::RouteError, resolve::DnsSink};

/// Production [`DnsSink`] backed by [`leas_dns::DnsResolver`].
pub struct DnsSinkAdapter {
    /// Shared resolver instance.
    pub resolver: Arc<leas_dns::DnsResolver>,
}

impl DnsSink for DnsSinkAdapter {
    fn lookup_ip<'a>(
        &self,
        host: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<IpAddr>, RouteError>> + Send + 'a>> {
        let resolver = Arc::clone(&self.resolver);
        Box::pin(async move {
            resolver
                .lookup_ip(host, true)
                .await
                // `Box<[IpAddr]>` → `Vec`: reuses the allocation, no copy.
                .map(Vec::from)
                .map_err(|e| RouteError::Resolve(e.to_string()))
        })
    }
}
