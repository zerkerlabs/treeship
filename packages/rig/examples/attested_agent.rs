//! End-to-end demo: a Rig `PortableTool` wrapped with Treeship attestation.
//!
//! Run with: `cargo run --example attested_agent`
//!
//! Uses a temp directory so it never touches your real `~/.treeship`.

use std::sync::Arc;

use rig::tool::PortableTool;
use rig_treeship::{AttestedExt, TreeshipLedger};
use serde::{Deserialize, Serialize};

#[derive(Debug, thiserror::Error)]
#[error("unknown city: {0}")]
struct UnknownCity(String);

#[derive(Serialize, Deserialize)]
struct WeatherArgs {
    city: String,
}

#[derive(Serialize)]
struct Weather {
    city: String,
    temp_c: f32,
}

/// A stand-in for a real tool (API call, shell command, DB write...).
struct GetWeather;

impl PortableTool for GetWeather {
    const NAME: &'static str = "get_weather";
    type Args = WeatherArgs;
    type Output = Weather;
    type Error = UnknownCity;

    fn description(&self) -> String {
        "Get the current temperature for a city".into()
    }

    fn parameters(&self) -> serde_json::Value {
        serde_json::json!({
            "type": "object",
            "properties": { "city": { "type": "string" } },
            "required": ["city"]
        })
    }

    async fn call(&self, args: WeatherArgs) -> Result<Weather, UnknownCity> {
        match args.city.as_str() {
            "Brooklyn" => Ok(Weather {
                city: args.city,
                temp_c: 27.0,
            }),
            "Tbilisi" => Ok(Weather {
                city: args.city,
                temp_c: 31.5,
            }),
            other => Err(UnknownCity(other.to_string())),
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let ledger = Arc::new(TreeshipLedger::open(dir.path(), "agent://weather-bot")?);

    // One line turns a bare Rig tool into an attested one.
    let tool = GetWeather.attested(ledger.clone());

    // Simulate an agent loop making tool calls.
    let w1 = tool
        .call(WeatherArgs {
            city: "Brooklyn".into(),
        })
        .await?;
    println!("call 1  -> {} is {}°C", w1.city, w1.temp_c);
    println!("receipt -> {}\n", ledger.head().unwrap());

    let w2 = tool
        .call(WeatherArgs {
            city: "Tbilisi".into(),
        })
        .await?;
    println!("call 2  -> {} is {}°C", w2.city, w2.temp_c);
    println!("receipt -> {}\n", ledger.head().unwrap());

    // A failing call still leaves a signed receipt (outcome: "error").
    let _ = tool
        .call(WeatherArgs {
            city: "Atlantis".into(),
        })
        .await;
    println!("call 3  -> failed (attested anyway)");
    println!("receipt -> {}\n", ledger.head().unwrap());

    // Walk and verify the whole chain, newest to genesis.
    let head = ledger.head().unwrap();
    let verified = ledger.verify_chain(&head)?;
    println!("chain verified: {} receipts", verified.length);
    for id in &verified.artifact_ids {
        println!("  {id}");
    }
    println!(
        "\npublic key (share for independent verification): {}",
        hex::encode(ledger.public_key_bytes())
    );

    Ok(())
}
