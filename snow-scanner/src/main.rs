#![feature(trivial_bounds)]
#[macro_use]
extern crate rouille;

use chrono::{NaiveDateTime, Utc};
use diesel::deserialize::{self, FromSqlRow};
use diesel::mysql::{Mysql, MysqlValue};
use diesel::sql_types::Text;
use hmac::{Hmac, Mac};
use rouille::{Request, Response, ResponseBody};
use sha2::Sha256;
use std::io::Write;
use std::str::FromStr;
use std::{env, fmt, thread};
use uuid::Uuid;

use hickory_client::client::SyncClient;
use hickory_client::rr::Name;
use hickory_client::tcp::TcpClientConnection;

use diesel::serialize::IsNull;
use diesel::{serialize, Connection, MysqlConnection};
use dns_ptr_resolver::{get_ptr, ResolvedResult};

pub mod models;
pub mod schema;

use crate::models::*;

// Create alias for HMAC-SHA256
type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, Clone, Copy, FromSqlRow)]
pub enum Scanners {
    Stretchoid,
    Binaryedge,
    Censys,
    InternetMeasurement,
}

trait IsStatic {
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

#[derive(Debug, PartialEq, Eq)]
struct ParseScannerError;

impl FromStr for Scanners {
    type Err = ParseScannerError;
    fn from_str(input: &str) -> Result<Self, Self::Err> {
        match input {
            "stretchoid" => Ok(Scanners::Stretchoid),
            "binaryedge" => Ok(Scanners::Binaryedge),
            "stretchoid.txt" => Ok(Scanners::Stretchoid),
            "binaryedge.txt" => Ok(Scanners::Binaryedge),
            "censys.txt" => Ok(Scanners::Censys),
            "internet-measurement.com.txt" => Ok(Scanners::InternetMeasurement),
            _ => Err(ParseScannerError {}),
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
        };

        Ok(IsNull::No)
    }
}

impl deserialize::FromSql<Text, Mysql> for Scanners {
    fn from_sql(bytes: MysqlValue) -> deserialize::Result<Self> {
        let value = <String as deserialize::FromSql<Text, Mysql>>::from_sql(bytes)?;
        match &value as &str {
            "stretchoid" => Ok(Scanners::Stretchoid),
            "binaryedge" => Ok(Scanners::Binaryedge),
            "internet-measurement.com" => Ok(Scanners::InternetMeasurement),
            _ => Err("Unrecognized enum variant".into()),
        }
    }
}

fn detect_scanner(ptr_result: &ResolvedResult) -> Result<Scanners, ()> {
    match ptr_result.result {
        Some(ref x)
            if x.trim_to(2)
                .eq_case(&Name::from_str("binaryedge.ninja.").expect("Should parse")) =>
        {
            Ok(Scanners::Binaryedge)
        }
        Some(ref x)
            if x.trim_to(2)
                .eq_case(&Name::from_str("stretchoid.com.").expect("Should parse")) =>
        {
            Ok(Scanners::Stretchoid)
        }
        _ => Err(()),
    }
}

fn handle_ip(conn: &mut MysqlConnection, ip: String) -> Result<Scanner, Option<ResolvedResult>> {
    let query_address = ip.parse().expect("To parse");

    let client = get_dns_client();
    let ptr_result: ResolvedResult = if let Ok(res) = get_ptr(query_address, client) {
        res
    } else {
        return Err(None);
    };

    match detect_scanner(&ptr_result) {
        Ok(scanner_name) => {
            let ip_type = if ip.contains(':') { 6 } else { 4 };
            let scanner = Scanner {
                ip: ip,
                ip_type: ip_type,
                scanner_name: scanner_name.clone(),
                ip_ptr: match ptr_result.result {
                    Some(ptr) => Some(ptr.to_string()),
                    None => None,
                },
                created_at: Utc::now().naive_utc(),
                updated_at: None,
                last_seen_at: None,
                last_checked_at: None,
            };

            match scanner.save(conn) {
                Ok(scanner) => Ok(scanner),
                Err(_) => Err(None),
            }
        }

        Err(_) => Err(Some(ptr_result)),
    }
}

static FORM: &str = r#"
<html>
    <head>
        <title>Wdes - snow scanner</title>
    </head>
    <body>
        <form action="/register" method="POST">
            <p><input type="email" name="email" placeholder="Your email" /></p>
            <p><button>Get an API key</button></p>
        </form>
        <form action="/report" method="POST">
            <p><input type="ip" name="ip" placeholder="An IPv4 or IPv6" /></p>
            <p><button>Report this IP</button></p>
        </form>
        <form action="/scan" method="POST">
            <p><input type="text" name="username" placeholder="Your username for logging purposes" /></p>
            <p><textarea name="ips"></textarea></p>
            <p><button>Scan</button></p>
        </form>
    </body>
</html>
"#;

fn handle_scan(conn: &mut MysqlConnection, request: &Request) -> Response {
    let data = try_or_400!(post_input!(request, {
        username: String,
        ips: String,
    }));

    if data.username.len() < 4 {
        return Response {
            status_code: 422,
            headers: vec![("Content-Type".into(), "text/plain; charset=utf-8".into())],
            data: ResponseBody::from_string("Invalid username"),
            upgrade: None,
        };
    }

    let task_group_id: Uuid = Uuid::now_v7();

    for ip in data.ips.lines() {
        let scan_task = ScanTask {
            task_group_id: task_group_id,
            cidr: ip.to_string(),
            created_by_username: data.username.clone(),
            created_at: Utc::now().naive_utc(),
            updated_at: None,
            started_at: None,
            still_processing_at: None,
            ended_at: None,
        };
        match scan_task.save(conn) {
            Ok(_) => println!("Added {}", ip.to_string()),
            Err(err) => eprintln!("Not added: {:?}", err),
        }
    }

    rouille::Response::html(format!("New task added: {} !", task_group_id))
}

fn handle_report(conn: &mut MysqlConnection, request: &Request) -> Response {
    let data = try_or_400!(post_input!(request, {
        ip: String,
    }));

    match handle_ip(conn, data.ip.clone()) {
        Ok(scanner) => rouille::Response::html(match scanner.scanner_name {
            Scanners::Binaryedge => format!(
                "Reported an escaped ninja! <b>{}</a> known as {:?}.",
                scanner.ip, scanner.ip_ptr
            ),
            Scanners::Stretchoid => format!(
                "Reported a stretchoid agent! <b>{}</a> known as {:?}.",
                scanner.ip, scanner.ip_ptr
            ),
            _ => format!("Not supported"),
        }),

        Err(ptr_result) => rouille::Response::html(format!(
            "The IP <b>{}</a> resolved as {:?} did not match known scanners patterns.",
            data.ip,
            match ptr_result {
                Some(res) => res.result,
                None => None,
            }
        )),
    }
}

fn handle_get_collection(request: &Request, static_data_dir: &str) -> Response {
    // The `match_assets` function tries to find a file whose name corresponds to the URL
    // of the request. The second parameter (`"."`) tells where the files to look for are
    // located.
    // In order to avoid potential security threats, `match_assets` will never return any
    // file outside of this directory even if the URL is for example `/../../foo.txt`.
    let response = rouille::match_assets(&request, static_data_dir);

    if response.is_success() {
        return response;
    }
    return Response {
        status_code: 404,
        headers: vec![("Content-Type".into(), "text/plain; charset=utf-8".into())],
        data: ResponseBody::from_string("File not found.\n"),
        upgrade: None,
    };
}

fn handle_list_scanners(
    conn: &mut MysqlConnection,
    static_data_dir: &str,
    scanner_name: Scanners,
    request: &Request,
) -> Response {
    if scanner_name.is_static() {
        // The `match_assets` function tries to find a file whose name corresponds to the URL
        // of the request. The second parameter (`"."`) tells where the files to look for are
        // located.
        // In order to avoid potential security threats, `match_assets` will never return any
        // file outside of this directory even if the URL is for example `/../../foo.txt`.
        let response = rouille::match_assets(&request, static_data_dir);

        if response.is_success() {
            return response;
        }
        return Response {
            status_code: 404,
            headers: vec![("Content-Type".into(), "text/plain; charset=utf-8".into())],
            data: ResponseBody::from_string("File not found.\n"),
            upgrade: None,
        };
    }
    if let Ok(scanners) = Scanner::list_names(scanner_name, conn) {
        Response {
            status_code: 200,
            headers: vec![("Content-Type".into(), "text/plain; charset=utf-8".into())],
            data: ResponseBody::from_string(scanners.join("\n")),
            upgrade: None,
        }
    } else {
        Response {
            status_code: 500,
            headers: vec![("Content-Type".into(), "text/plain; charset=utf-8".into())],
            data: ResponseBody::from_string("Unable to list scanners"),
            upgrade: None,
        }
    }
}

static SCAN_TASKS_HEAD: &str = r#"
<html>
    <head>
        <title>Wdes - snow scanner | Scan tasks</title>
    </head>
    <body>
    <table>
        <thead>
            <tr>
                <th>CIDR</th>
                <th>Started at</th>
                <th>Still processing at</th>
                <th>Ended at</th>
            </tr>
        </thead>
        <tbody>
"#;

static SCAN_TASKS_FOOT: &str = r#"
        </tbody>
      </table>
    </body>
</html>
"#;

fn handle_list_scan_tasks(conn: &mut MysqlConnection) -> Response {
    let mut html_data: Vec<String> = vec![SCAN_TASKS_HEAD.to_string()];

    if let Ok(scan_tasks) = ScanTask::list(conn) {
        for row in scan_tasks {
            let cidr: String = row.cidr;
            let started_at: Option<NaiveDateTime> = row.started_at;
            let still_processing_at: Option<NaiveDateTime> = row.still_processing_at;
            let ended_at: Option<NaiveDateTime> = row.ended_at;
            html_data.push(format!(
                "
                <tr>
                    <td>{cidr}</td>
                    <td>{:#?}</td>
                    <td>{:#?}</td>
                    <td>{:#?}</td>
                </tr>
                ",
                started_at, still_processing_at, ended_at
            ));
        }

        html_data.push(SCAN_TASKS_FOOT.to_string());

        Response {
            status_code: 200,
            headers: vec![("Content-Type".into(), "text/html; charset=utf-8".into())],
            data: ResponseBody::from_string(html_data.join("\n")),
            upgrade: None,
        }
    } else {
        Response {
            status_code: 500,
            headers: vec![("Content-Type".into(), "text/plain; charset=utf-8".into())],
            data: ResponseBody::from_string("Unable to list scan tasks"),
            upgrade: None,
        }
    }
}

fn get_connection(database_url: &str) -> MysqlConnection {
    MysqlConnection::establish(&database_url)
        .unwrap_or_else(|_| panic!("Error connecting to {}", database_url))
}

fn get_dns_client() -> SyncClient<TcpClientConnection> {
    let server = "1.1.1.1:53".parse().expect("To parse");
    let dns_conn =
        TcpClientConnection::with_timeout(server, std::time::Duration::new(5, 0)).unwrap();
    SyncClient::new(dns_conn)
}

fn main() -> Result<(), ()> {
    let server_address: String = if let Ok(env) = env::var("SERVER_ADDRESS") {
        env
    } else {
        "localhost:8000".to_string()
    };

    println!("Now listening on {}", server_address);

    let db_url: String = if let Ok(env) = env::var("DB_URL") {
        env
    } else {
        "./snow-scanner.sqlite".to_string()
    };

    let static_data_dir: String = match env::var("STATIC_DATA_DIR") {
        Ok(val) => val,
        Err(_) => "../data/".to_string(),
    };

    let conn = &mut get_connection(db_url.as_str());
    /*
    thread::spawn(move || {
        let conn = &mut get_connection(db_url.as_str());
        // Reset scan tasks
        let _ = conn.execute("UPDATE scan_tasks SET updated_at = :updated_at, still_processing_at = NULL, started_at = NULL WHERE (still_processing_at IS NOT NULL OR started_at IS NOT NULL) AND ended_at IS NULL",
            named_params! {
                ":updated_at": Utc::now().naive_utc().to_string(),
            }).unwrap();

        loop {
            let mut stmt = conn.prepare("SELECT task_group_id, cidr FROM scan_tasks WHERE started_at IS NULL ORDER BY created_at ASC").unwrap();
            let mut rows = stmt.query(named_params! {}).unwrap();
            println!("Waiting for jobs");
            while let Some(row) = rows.next().unwrap() {
                let task_group_id: String = row.get(0).unwrap();
                let cidr_str: String = row.get(1).unwrap();
                let cidr: IpCidr = cidr_str.parse().expect("Should parse CIDR");
                println!("Picking up: {} -> {}", task_group_id, cidr);
                println!("Range, from {} to {}", cidr.first(), cidr.last());
                let _ = conn.execute("UPDATE scan_tasks SET updated_at = :updated_at, started_at = :started_at WHERE cidr = :cidr AND task_group_id = :task_group_id",
                    named_params! {
                        ":updated_at": Utc::now().naive_utc().to_string(),
                        ":started_at": Utc::now().naive_utc().to_string(),
                        ":cidr": cidr_str,
                        ":task_group_id": task_group_id,
                    }).unwrap();
                let addresses = cidr.iter().addresses();
                let count = addresses.count();
                let mut current = 0;
                for addr in addresses {
                    match handle_ip(conn, addr.to_string()) {
                        Ok(scanner) => println!("Processed {}", scanner.ip),
                        Err(_) => println!("Processed {}", addr),
                    }
                    current += 1;
                    if (current / count) % 10 == 0 {
                        let _ = conn.execute("UPDATE scan_tasks SET updated_at = :updated_at, still_processing_at = :still_processing_at WHERE cidr = :cidr AND task_group_id = :task_group_id",
                            named_params! {
                                ":updated_at": Utc::now().naive_utc().to_string(),
                                ":still_processing_at": Utc::now().naive_utc().to_string(),
                                ":cidr": cidr_str,
                                ":task_group_id": task_group_id,
                            }).unwrap();
                    }
                }
                let _ = conn.execute("UPDATE scan_tasks SET updated_at = :updated_at, ended_at = :ended_at WHERE cidr = :cidr AND task_group_id = :task_group_id",
                    named_params! {
                        ":updated_at": Utc::now().naive_utc().to_string(),
                        ":ended_at": Utc::now().naive_utc().to_string(),
                        ":cidr": cidr_str,
                        ":task_group_id": task_group_id,
                    }).unwrap();
            }

            let two_hundred_millis = Duration::from_millis(500);
            thread::sleep(two_hundred_millis);
        }
    });*/

    rouille::start_server(server_address, move |request| {
        router!(request,
            (GET) (/) => {
                rouille::Response::html(FORM)
            },

            (GET) (/ping) => {
                rouille::Response::text("pong")
            },

            (POST) (/report) => {handle_report(conn, &request)},
            (POST) (/scan) => {handle_scan(conn, &request)},
            (GET) (/scan/tasks) => {
                handle_list_scan_tasks(conn)
            },

            (POST) (/register) => {
                let data = try_or_400!(post_input!(request, {
                    email: String,
                }));

                // We just print what was received on stdout. Of course in a real application
                // you probably want to process the data, eg. store it in a database.
                println!("Received data: {:?}", data);


                let mut mac = HmacSha256::new_from_slice(b"my secret and secure key")
                    .expect("HMAC can take key of any size");
                mac.update(data.email.as_bytes());

                // `result` has type `CtOutput` which is a thin wrapper around array of
                // bytes for providing constant time equality check
                let result = mac.finalize();
                // To get underlying array use `into_bytes`, but be careful, since
                // incorrect use of the code value may permit timing attacks which defeats
                // the security provided by the `CtOutput`
                let code_bytes = result.into_bytes();
                rouille::Response::html(format!("Success! <b>{}</a>.", hex::encode(code_bytes)))
            },

            (GET) (/scanners/{scanner_name: Scanners}) => {
                handle_list_scanners(conn, &static_data_dir, scanner_name, &request)
            },
            (GET) (/collections/{vendor_name: String}/{file_name: String}) => {
                handle_get_collection(&request, &static_data_dir)
            },
            (GET) (/{api_key: String}/scanners/{scanner_name: String}) => {
                let mut mac = HmacSha256::new_from_slice(b"my secret and secure key")
                    .expect("HMAC can take key of any size");

                mac.update(b"williamdes@wdes.fr");

                println!("{}", api_key);
                let hex_key = hex::decode(&api_key).unwrap();
                // `verify_slice` will return `Ok(())` if code is correct, `Err(MacError)` otherwise
                mac.verify_slice(&hex_key).unwrap();

                rouille::Response::empty_404()
            },
            // The code block is called if none of the other blocks matches the request.
            // We return an empty response with a 404 status code.
            _ => rouille::Response::empty_404()
        )
    });
}
