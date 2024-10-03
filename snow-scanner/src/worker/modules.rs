use std::{net::IpAddr, str::FromStr};

use cidr::IpCidr;
use rocket_ws::Message as RocketMessage;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

#[derive(Debug, Clone, PartialEq)]
pub struct Network(pub IpCidr);

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
#[serde(tag = "type", content = "request")]
pub enum WorkerMessages {
    #[serde(rename = "auth_request")]
    AuthenticateRequest { login: String },
    #[serde(rename = "get_work")]
    GetWorkRequest {},
    #[serde(rename = "do_work")]
    DoWorkRequest { neworks: Vec<Network> },
    #[serde(rename = "scanner_found")]
    ScannerFoundResponse { name: String, address: IpAddr },
    #[serde(rename = "")]
    Invalid { err: String },
}

impl<'de> Deserialize<'de> for Network {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = <String>::deserialize(deserializer)?;

        let k: &str = s.as_str();

        match IpCidr::from_str(k) {
            Ok(d) => Ok(Network(d)),
            Err(err) => Err(serde::de::Error::custom(format!(
                "Unsupported value {k}: {err}"
            ))),
        }
    }
}

impl Serialize for Network {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.0.to_string().as_str())
    }
}

impl ToString for WorkerMessages {
    fn to_string(&self) -> String {
        serde_json::to_string(&self).expect("To serialize").into()
    }
}

impl Into<WorkerMessages> for String {
    fn into(self) -> WorkerMessages {
        let req: Result<WorkerMessages, serde_json::Error> = serde_json::from_str(self.as_str());
        match req {
            Ok(d) => d,
            Err(err) => WorkerMessages::Invalid {
                err: err.to_string(),
            },
        }
    }
}

impl TryInto<WorkerMessages> for RocketMessage {
    type Error = String;

    fn try_into(self) -> Result<WorkerMessages, Self::Error> {
        match self {
            RocketMessage::Text(data) => {
                let data: WorkerMessages = data.into();
                Ok(data)
            }
            _ => Err("Only text is supported".to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use cidr::IpCidr;

    use super::*;

    #[test]
    fn deserialize_do_work_empty() {
        let data = "{\"type\":\"do_work\",\"request\":{\"neworks\":[]}}";
        let result: WorkerMessages = data.to_string().into();
        assert_eq!(
            result,
            WorkerMessages::DoWorkRequest {
                neworks: [].to_vec()
            }
        );
    }

    #[test]
    fn deserialize_do_work() {
        let data = "{\"type\":\"do_work\",\"request\":{\"neworks\":[\"127.0.0.0/31\"]}}";
        let result: WorkerMessages = data.to_string().into();
        let cidr: IpCidr = IpCidr::from_str("127.0.0.0/31").unwrap();
        assert_eq!(
            result,
            WorkerMessages::DoWorkRequest {
                neworks: [Network(cidr)].to_vec()
            }
        );
    }
}
