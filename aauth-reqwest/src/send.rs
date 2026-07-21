use reqwest::{Request, Response};

use aauth::Result;

#[async_trait::async_trait]
pub(crate) trait SignedSend {
    async fn send(&mut self, req: Request) -> Result<Response>;
}
