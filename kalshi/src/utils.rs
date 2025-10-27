use std::{
    error::Error,
    time::{SystemTime, UNIX_EPOCH},
};

use base64::{prelude::BASE64_STANDARD, Engine};
use openssl::sign::Signer;
use openssl::hash::MessageDigest;
use openssl::pkey::PKey;
use openssl::rsa::Padding;
use openssl::sign::RsaPssSaltlen;
use reqwest::Method;

use crate::TradingEnvironment;
// MACROS

#[macro_export]
#[doc(hidden)]
macro_rules! add_param {
    ($params:ident, $param_name:expr, $param_value:expr) => {
        if let Some(param) = $param_value {
            $params.push(($param_name, param.to_string()));
        }
    };
}

// Helper to build the base url

pub const fn build_base_url(trading_env: TradingEnvironment) -> &'static str {
    match trading_env {
        TradingEnvironment::LiveMarketMode => "https://api.elections.kalshi.com/trade-api/v2",
        TradingEnvironment::LegacyLiveMarketMode => "https://trading-api.kalshi.com/trade-api/v2",
        TradingEnvironment::DemoMode => "https://demo-api.kalshi.co/trade-api/v2",
    }
}

pub const fn build_ws_url(trading_env: TradingEnvironment) -> &'static str {
    match trading_env {
        TradingEnvironment::LiveMarketMode => "wss://api.elections.kalshi.com/trade-api/ws/v2",
        TradingEnvironment::LegacyLiveMarketMode => "wss://trading-api.kalshi.com/v1/ws",
        TradingEnvironment::DemoMode => "wss://demo-api.kalshi.co/trade-api/ws/v2",
    }
}

pub(super) fn api_key_headers(
    key_id: impl AsRef<str>,
    p_key: &PKey<openssl::pkey::Private>,
    path: impl AsRef<str>,
    method: Method,
) -> Result<Vec<(&'static str, String)>, Box<dyn Error>> {
    let mut headers = Vec::new();
    let ts = SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis();
    let method = method.as_str();
    let path = path.as_ref();
    let msg_string = format!("{ts}{method}{path}");

    // Create a fresh Signer for each request to ensure proper state
    let mut signer = Signer::new(MessageDigest::sha256(), p_key)?;
    signer.set_rsa_padding(Padding::PKCS1_PSS)?;
    signer.set_rsa_pss_saltlen(RsaPssSaltlen::DIGEST_LENGTH)?;

    // Raw bytes of signature
    let sig_raw = signer.sign_oneshot_to_vec(msg_string.as_bytes())?;
    // base64 encoded sig string
    let sig: String = BASE64_STANDARD.encode(sig_raw);
    headers.push(("KALSHI-ACCESS-KEY", key_id.as_ref().to_string()));
    headers.push(("KALSHI-ACCESS-SIGNATURE", sig));
    headers.push(("KALSHI-ACCESS-TIMESTAMP", ts.to_string()));
    Ok(headers)
}
