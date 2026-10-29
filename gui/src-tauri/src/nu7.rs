//! Read-only NU7 availability endpoint. Spending repeats the core checks.
use argos_core::{models::ZeckNetwork, nu7::SproutAvailability};

#[tauri::command]
pub async fn sprout_nu7_status(
    network: String,
    lightwalletd_url: String,
    confirmation_sources: Option<Vec<String>>,
) -> Result<SproutAvailability, String> {
    let network = match network.as_str() {
        "mainnet" => ZeckNetwork::Mainnet,
        "testnet" => ZeckNetwork::Testnet,
        _ => return Err("choose mainnet or testnet".to_owned()),
    };
    let sources = confirmation_sources.unwrap_or_default();
    let raw: Vec<&str> = sources.iter().map(String::as_str).collect();
    let sources = match argos_core::lightwalletd::parse_confirmation_sources(&raw) {
        Ok(sources) => sources,
        Err(error) => return Ok(SproutAvailability::unknown(network, error)),
    };
    Ok(argos_core::nu7::query_sprout_availability(network, &lightwalletd_url, &sources).await)
}
