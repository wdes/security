use diesel::deserialize;
use diesel::deserialize::FromSqlRow;
use diesel::mysql::Mysql;
use diesel::mysql::MysqlValue;
use diesel::serialize;
use diesel::serialize::IsNull;
use diesel::sql_types::Text;
use hickory_resolver::Name;
use rocket::request::FromParam;
use std::str::FromStr;

use serde::{Deserialize, Deserializer};
use std::io::Write;

#[derive(Debug, Clone, Copy, FromSqlRow, PartialEq)]
pub enum Scanners {
    Stretchoid,
    Binaryedge,
    Shadowserver,
    Censys,
    InternetMeasurement,
    Anssi,
}

pub trait ScannerMethods {
    fn is_static(self: &Self) -> bool;
    fn static_file_name(self: &Self) -> Option<&str>;
    fn funny_name(self: &Self) -> &str;
}

impl ScannerMethods for Scanners {
    fn is_static(self: &Self) -> bool {
        self.static_file_name().is_some()
    }

    fn static_file_name(self: &Self) -> Option<&str> {
        match self {
            Self::Censys => Some("censys.txt"),
            Self::InternetMeasurement => Some("internet-measurement.com.txt"),
            Self::Anssi => Some("anssi.txt"),
            _ => None,
        }
    }

    fn funny_name(self: &Self) -> &str {
        match self {
            Self::Stretchoid => "stretchoid agent",
            Self::Binaryedge => "binaryedge ninja",
            Self::Censys => "Censys node",
            Self::InternetMeasurement => "internet measurement probe",
            Self::Shadowserver => "cloudy shadowserver",
            _ => (*self).into(),
        }
    }
}

impl FromParam<'_> for Scanners {
    type Error = String;

    fn from_param(param: &'_ str) -> Result<Self, Self::Error> {
        param.try_into()
    }
}

impl<'de> Deserialize<'de> for Scanners {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = <Vec<String>>::deserialize(deserializer)?;
        let k: &str = s[0].as_str();
        match k.try_into() {
            Ok(scanners) => Ok(scanners),
            Err(v) => Err(serde::de::Error::custom(format!("Unknown value: {}", v))),
        }
    }
}

impl ToString for Scanners {
    fn to_string(&self) -> String {
        let res: &str = (*self).into();
        res.to_string()
    }
}

impl Into<&str> for Scanners {
    fn into(self) -> &'static str {
        match self {
            Self::Stretchoid => "stretchoid",
            Self::Binaryedge => "binaryedge",
            Self::Censys => "censys",
            Self::InternetMeasurement => "internet-measurement.com",
            Self::Shadowserver => "shadowserver",
            Self::Anssi => "anssi",
        }
    }
}

impl serialize::ToSql<Text, Mysql> for Scanners {
    fn to_sql(&self, out: &mut serialize::Output<Mysql>) -> serialize::Result {
        let res: &str = (*self).into();
        out.write_all(res.as_bytes())?;

        Ok(IsNull::No)
    }
}

impl deserialize::FromSql<Text, Mysql> for Scanners {
    fn from_sql(bytes: MysqlValue) -> deserialize::Result<Self> {
        let value = <String as deserialize::FromSql<Text, Mysql>>::from_sql(bytes)?;
        let value = &value as &str;
        let value: Result<Scanners, String> = value.try_into();
        match value {
            Ok(d) => Ok(d),
            Err(err) => Err(err.into()),
        }
    }
}

// Used for FromSql & FromParam & Deserialize
impl TryInto<Scanners> for &str {
    type Error = String;

    fn try_into(self) -> Result<Scanners, Self::Error> {
        match self.replace(".txt", "").as_str() {
            "stretchoid" => Ok(Scanners::Stretchoid),
            "binaryedge" => Ok(Scanners::Binaryedge),
            "internet-measurement.com" => Ok(Scanners::InternetMeasurement),
            "shadowserver" => Ok(Scanners::Shadowserver),
            "censys" => Ok(Scanners::Censys),
            "anssi" => Ok(Scanners::Anssi),
            value => Err(format!("Invalid value: {value}")),
        }
    }
}

// Used by the DNS logic
impl TryInto<Scanners> for Name {
    type Error = String;

    fn try_into(self) -> Result<Scanners, Self::Error> {
        match self {
            ref name
                if name
                    .trim_to(2)
                    .eq_case(&Name::from_str("binaryedge.ninja.").expect("Should parse")) =>
            {
                Ok(Scanners::Binaryedge)
            }
            ref name
                if name
                    .trim_to(2)
                    .eq_case(&Name::from_str("stretchoid.com.").expect("Should parse")) =>
            {
                Ok(Scanners::Stretchoid)
            }
            ref name
                if name
                    .trim_to(2)
                    .eq_case(&Name::from_str("shadowserver.org.").expect("Should parse")) =>
            {
                Ok(Scanners::Shadowserver)
            }
            ref name => Err(format!("Invalid hostname: {name}")),
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn test_detect_scanner_from_name() {
        let ptr = Name::from_str("scan-47e.shadowserver.org.").unwrap();

        let res: Result<Scanners, String> = ptr.try_into();

        assert_eq!(res.unwrap(), Scanners::Shadowserver);
    }
}
