use std::{future::Future, time::Duration};

/// Wait until zcashd's wallet has indexed enough confirmed, spendable funds.
///
/// The `generate` RPC waits for the chain tip, but wallet notification can
/// finish slightly later. Tests that call `sendtoaddress` immediately after
/// mining otherwise fail intermittently with `Insufficient funds`.
pub async fn wait_for_spendable_balance<F, Fut>(minimum_zec: f64, mut read_balance: F)
where
    F: FnMut() -> Fut,
    Fut: Future<Output = serde_json::Value>,
{
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    loop {
        let balance = read_balance()
            .await
            .as_f64()
            .expect("numeric wallet balance");
        if balance >= minimum_zec {
            return;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "zcashd wallet did not index {minimum_zec} ZEC of spendable funds within 30 seconds"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}
