use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(tag = "type", content = "request")]
pub enum WorkerMessages {
    #[serde(rename = "auth_request")]
    AuthenticateRequest { login: String },
    #[serde(rename = "get_work")]
    GetWorkRequest {},
    #[serde(rename = "do_work")]
    DoWorkRequest {},
    #[serde(rename = "")]
    Invalid,
}

impl ToString for WorkerMessages {
    fn to_string(&self) -> String {
        serde_json::to_string(&self).expect("To serialize").into()
    }
}

impl Into<WorkerMessages> for String {
    fn into(self) -> WorkerMessages {
        let req: Result<WorkerMessages, serde_json::Error> =
            serde_json::from_str(self.as_str());
        match req {
            Ok(d) => d,
            Err(_) => WorkerMessages::Invalid,
        }
    }
}
