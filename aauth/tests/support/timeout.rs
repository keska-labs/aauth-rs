//! Short poll caps so integration tests fail fast instead of waiting on poll loops.

/// Client/server poll loop cap used by the test harness.
pub const TEST_POLL_MAX_SECS: u64 = 5;
