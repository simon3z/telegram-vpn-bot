use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::error::Error as StdError;
use std::pin::Pin;

const TELEGRAM_API_BASE: &str = "https://api.telegram.org";

/// Client for the Telegram Bot API. Handles long polling and outgoing calls.
#[derive(Clone)]
pub struct TelegramClient {
    token: String,
    http: Client,
}

/// A single Telegram update from long polling.
#[derive(Debug, Deserialize)]
pub struct Update {
    pub update_id: i64,
    #[serde(default)]
    pub message: Option<Message>,
}

/// Incoming message.
#[derive(Debug, Deserialize)]
pub struct Message {
    pub chat: Chat,
    #[serde(default)]
    pub from: Option<User>,
    #[serde(default)]
    pub text: Option<String>,
}

/// Chat information.
#[derive(Debug, Deserialize)]
pub struct Chat {
    pub id: i64,
}

/// User information.
#[derive(Debug, Deserialize)]
pub struct User {
    pub id: i64,
}

/// Bot information returned by /getMe.
#[derive(Debug, Deserialize)]
pub struct BotInfo {
    pub username: String,
}

#[derive(Serialize)]
struct SendMessageRequest<'a> {
    chat_id: i64,
    text: &'a str,
    disable_web_page_preview: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    parse_mode: Option<&'a str>,
}

#[derive(Serialize)]
struct SendChatActionRequest<'a> {
    chat_id: i64,
    action: &'a str,
}

#[derive(Debug, Deserialize)]
struct GetMeResponse {
    ok: bool,
    #[serde(default)]
    description: Option<String>,
    result: BotInfo,
}

#[derive(Debug, Deserialize)]
struct SendMessageResponse {
    ok: bool,
    #[serde(default)]
    description: Option<String>,
}

#[derive(Debug, Deserialize)]
struct GetUpdatesResponse {
    ok: bool,
    #[serde(default)]
    description: Option<String>,
    #[serde(default)]
    result: Vec<Update>,
}

impl TelegramClient {
    /// Create a new client with the given bot token.
    pub async fn new(token: &str) -> Result<Self, String> {
        let http = Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .map_err(|e| format!("Failed to build HTTP client: {}", e))?;

        Ok(Self {
            token: token.to_string(),
            http,
        })
    }

    /// Fetch bot info (/getMe).
    pub async fn get_me(&self) -> Result<BotInfo, String> {
        let url = format!("{}/bot{}/getMe", TELEGRAM_API_BASE, self.token);
        let resp = self
            .http
            .get(&url)
            .send()
            .await
            .map_err(|e| format!("getMe request failed: {}", e))?;

        let body: GetMeResponse = resp
            .json()
            .await
            .map_err(|e| format!("Failed to parse getMe response: {}", e))?;

        if !body.ok {
            return Err(format!(
                "Telegram API error: {}",
                body.description.unwrap_or_default()
            ));
        }

        Ok(body.result)
    }

    /// Send a text message. Pass `"HTML"` or `"Markdown"` as parse_mode to enable formatting.
    pub async fn send_message(
        &self,
        chat_id: i64,
        text: &str,
        parse_mode: Option<&str>,
    ) -> Result<(), String> {
        let url = format!("{}/bot{}/sendMessage", TELEGRAM_API_BASE, self.token);

        let body = SendMessageRequest {
            chat_id,
            text,
            disable_web_page_preview: true,
            parse_mode,
        };

        let resp = self
            .http
            .post(&url)
            .json(&body)
            .send()
            .await
            .map_err(|e| format!("sendMessage request failed: {}", e))?;

        let api_resp: SendMessageResponse = resp
            .json()
            .await
            .map_err(|e| format!("Failed to parse sendMessage response: {}", e))?;

        if !api_resp.ok {
            return Err(format!(
                "sendMessage failed: {}",
                api_resp.description.unwrap_or_default()
            ));
        }

        Ok(())
    }

    /// Send a chat action (e.g., "typing", "upload_photo", "record_video").
    pub async fn send_chat_action(&self, chat_id: i64, action: &str) -> Result<(), String> {
        let url = format!("{}/bot{}/sendChatAction", TELEGRAM_API_BASE, self.token);

        let body = SendChatActionRequest { chat_id, action };

        let resp = self
            .http
            .post(&url)
            .json(&body)
            .send()
            .await
            .map_err(|e| format!("sendChatAction request failed: {}", e))?;

        let api_resp: SendMessageResponse = resp
            .json()
            .await
            .map_err(|e| format!("Failed to parse sendChatAction response: {}", e))?;

        if !api_resp.ok {
            return Err(format!(
                "sendChatAction failed: {}",
                api_resp.description.unwrap_or_default()
            ));
        }

        Ok(())
    }

    /// Poll the Telegram API for pending updates. Returns either the list of
    /// updates or an error describing why the poll failed.
    ///
    /// Network failures produce an `Err`; malformed responses are logged at
    /// warning level and also returned as `Err` so the caller can retry after
    /// a short pause.
    async fn fetch_updates(
        &self,
        offset: i64,
        timeout: u64,
        limit: u64,
    ) -> Result<Vec<Update>, String> {
        let url = format!(
            "{}/bot{}/getUpdates?offset={}&limit={}&timeout={}",
            TELEGRAM_API_BASE, self.token, offset, limit, timeout,
        );

        let resp = self.http.get(&url).send().await.map_err(|e| {
            let detail = reqwest_error_detail(&e);
            let path = url.trim_start_matches("https://api.telegram.org");
            tracing::warn!("getUpdates request failed: {detail}\nURL: {path}");
            String::from("request failed")
        })?;

        let status = resp.status();
        if !status.is_success() {
            let body_text = resp
                .text()
                .await
                .unwrap_or_else(|_| "(could not read body)".to_string());
            tracing::error!(
                "getUpdates returned HTTP {}: {}\nBody: {}",
                status.as_u16(),
                status.canonical_reason().unwrap_or("unknown"),
                body_text,
            );
            return Err("non-success HTTP response".into());
        }

        let body: GetUpdatesResponse = resp
            .json()
            .await
            .map_err(|e| format!("failed to parse getUpdates response as JSON: {e}"))?;

        if !body.ok {
            tracing::error!(
                "getUpdates API error: {}",
                body.description.unwrap_or_default()
            );
        }

        Ok(body.result)
    }

    /// Run the long-polling loop, calling `handler` for each incoming update.
    /// Retries on network errors with back-off pauses.
    pub async fn run_polling<F>(&self, timeout: u64, limit: u64, handler: F) -> Result<(), String>
    where
        F: Fn(&Update) -> Pin<Box<dyn std::future::Future<Output = ()> + Send + '_>>
            + Send
            + Sync
            + 'static,
    {
        let mut offset: i64 = 0;

        loop {
            let updates = match self.fetch_updates(offset, timeout, limit).await {
                Ok(u) => u,
                Err(_) => {
                    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                    continue;
                }
            };

            if !updates.is_empty() {
                offset = updates.last().unwrap().update_id + 1;

                for update in updates {
                    let fut = handler(&update);
                    fut.await;
                }
            }
        }
    }
}

// --- Error helpers ---

/// Extract the deepest, most informative error message from a reqwest error chain.
fn reqwest_error_detail(e: &reqwest::Error) -> String {
    let mut best = format!("{e}");
    let mut source: Option<&dyn StdError> = e.source();
    while let Some(err) = source {
        let msg = format!("{err}");
        if !msg.is_empty() {
            best = msg;
        }
        source = err.source();
    }
    best
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A client can be constructed with any token string (valid or not).
    #[tokio::test]
    async fn test_new_client_accepts_any_token_string() {
        let _client = TelegramClient::new("fake-token-for-test").await.unwrap();
    }

    /// Sending a message with an invalid token must fail gracefully.
    #[tokio::test]
    async fn test_send_message_invalid_token_returns_error() {
        let client = TelegramClient::new("invalid_token_for_test").await.unwrap();

        let result = client.send_message(123_456, "hello", None).await;

        // The HTTP call will fail since there is no real bot. We just verify
        // that the function returns an error (not panics).
        assert!(result.is_err());
    }

    /// Chat action with an invalid token also fails gracefully.
    #[tokio::test]
    async fn test_send_chat_action_invalid_token_returns_error() {
        let client = TelegramClient::new("invalid_token_for_test").await.unwrap();

        let result = client.send_chat_action(123_456, "typing").await;

        assert!(result.is_err());
    }

    /// getMe with an invalid token produces a clear error message.
    #[tokio::test]
    async fn test_get_me_invalid_token_returns_error() {
        let client = TelegramClient::new("invalid_token_for_test").await.unwrap();

        let result = client.get_me().await;

        assert!(result.is_err());
    }

    /// Sending with an explicit parse mode still exercises the same path.
    #[tokio::test]
    async fn test_send_message_with_parse_mode_invalid_token() {
        let client = TelegramClient::new("invalid_token_for_test").await.unwrap();

        let result = client
            .send_message(123_456, "<b>bold</b>", Some("HTML"))
            .await;

        assert!(result.is_err());
    }
}
