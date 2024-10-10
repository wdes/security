use diesel::deserialize;
use diesel::deserialize::FromSqlRow;
use diesel::mysql::Mysql;
use diesel::mysql::MysqlValue;
use diesel::serialize;
use diesel::serialize::IsNull;
use diesel::sql_types::Text;
use rocket::request::FromParam;

use serde::{Deserialize, Deserializer};
use std::fmt;
use std::io::Write;

#[derive(Debug, Clone, Copy, FromSqlRow, PartialEq)]
pub enum Scanners {
    Stretchoid,
    Binaryedge,
    Shadowserver,
    Censys,
    InternetMeasurement,
}

pub trait IsStatic {
    fn is_static(self: &Self) -> bool;
}

impl IsStatic for Scanners {
    fn is_static(self: &Self) -> bool {
        match self {
            Scanners::Censys => true,
            Scanners::InternetMeasurement => true,
            _ => false,
        }
    }
}

impl FromParam<'_> for Scanners {
    type Error = String;

    fn from_param(param: &'_ str) -> Result<Self, Self::Error> {
        match param {
            "stretchoid" => Ok(Scanners::Stretchoid),
            "binaryedge" => Ok(Scanners::Binaryedge),
            "shadowserver" => Ok(Scanners::Shadowserver),
            "stretchoid.txt" => Ok(Scanners::Stretchoid),
            "binaryedge.txt" => Ok(Scanners::Binaryedge),
            "shadowserver.txt" => Ok(Scanners::Shadowserver),
            "censys.txt" => Ok(Scanners::Censys),
            "internet-measurement.com.txt" => Ok(Scanners::InternetMeasurement),
            v => Err(format!("Unknown value: {v}")),
        }
    }
}

impl<'de> Deserialize<'de> for Scanners {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = <Vec<String>>::deserialize(deserializer)?;
        let k: &str = s[0].as_str();
        match k {
            "stretchoid" => Ok(Scanners::Stretchoid),
            "binaryedge" => Ok(Scanners::Binaryedge),
            "shadowserver" => Ok(Scanners::Shadowserver),
            "stretchoid.txt" => Ok(Scanners::Stretchoid),
            "binaryedge.txt" => Ok(Scanners::Binaryedge),
            "shadowserver.txt" => Ok(Scanners::Shadowserver),
            "censys.txt" => Ok(Scanners::Censys),
            "internet-measurement.com.txt" => Ok(Scanners::InternetMeasurement),
            v => Err(serde::de::Error::custom(format!(
                "Unknown value: {}",
                v.to_string()
            ))),
        }
    }
}

impl fmt::Display for Scanners {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}",
            match self {
                Self::Stretchoid => "stretchoid",
                Self::Binaryedge => "binaryedge",
                Self::Censys => "censys",
                Self::InternetMeasurement => "internet-measurement.com",
                Self::Shadowserver => "shadowserver",
            }
        )
    }
}

impl serialize::ToSql<Text, Mysql> for Scanners {
    fn to_sql(&self, out: &mut serialize::Output<Mysql>) -> serialize::Result {
        match *self {
            Self::Stretchoid => out.write_all(b"stretchoid")?,
            Self::Binaryedge => out.write_all(b"binaryedge")?,
            Self::Censys => out.write_all(b"censys")?,
            Self::InternetMeasurement => out.write_all(b"internet-measurement.com")?,
            Self::Shadowserver => out.write_all(b"shadowserver")?,
        };

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

impl TryInto<Scanners> for &str {
    type Error = String;

    fn try_into(self) -> Result<Scanners, Self::Error> {
        match self {
            "stretchoid" => Ok(Scanners::Stretchoid),
            "binaryedge" => Ok(Scanners::Binaryedge),
            "internet-measurement.com" => Ok(Scanners::InternetMeasurement),
            "shadowserver" => Ok(Scanners::Shadowserver),
            value => Err(format!("Invalid value: {value}")),
        }
    }
}
