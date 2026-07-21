use reqwest::{Request, Response};

use crate::error::Result;

#[trait_variant::make(Send)]
#[dynosaur::dynosaur(DynSignedSend = dyn(box) SignedSend, bridge(dyn))]
pub(crate) trait SignedSend {
    async fn send(&mut self, req: Request) -> Result<Response>;
}
