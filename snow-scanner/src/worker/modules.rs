use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum WorkerMessages {
    AuthenticateRequest { login: String },
    FooRequest { username: String },
    String,
}
