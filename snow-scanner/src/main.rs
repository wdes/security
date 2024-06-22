#[macro_use]
extern crate rouille;

use chrono::Utc;
use hmac::{Hmac, Mac};
use rouille::{Request, Response, ResponseBody};
use rusqlite::types::ToSqlOutput;
use rusqlite::{named_params, Connection, OpenFlags, Result, ToSql};
use sha2::Sha256;
use std::fmt;
use std::str::FromStr;
use std::sync::Mutex;

use hickory_client::client::SyncClient;
use hickory_client::rr::Name;
use hickory_client::tcp::TcpClientConnection;

use dns_ptr_resolver::{get_ptr, ResolvedResult};

// Create alias for HMAC-SHA256
type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, Clone)]
enum Scanners {
    Strechoid,
    Binaryedge,
}

impl fmt::Display for Scanners {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}",
            match self {
                Self::Strechoid => "strechoid",
                Self::Binaryedge => "binaryedge",
            }
        )
    }
}
impl ToSql for Scanners {
    /// Converts Rust value to SQLite value
    fn to_sql(&self) -> Result<ToSqlOutput<'_>> {
        match self {
            Self::Strechoid => Ok("strechoid".into()),
            Self::Binaryedge => Ok("binaryedge".into()),
        }
    }
}

#[derive(Debug)]
struct Scanner {
    ip: String,
    ip_type: u8,
    scanner_name: Scanners,
    created_at: String,
    updated_at: String,
    last_seen_at: String,
    last_checked_at: String,
}

fn save_scanner(conn: &Connection, scanner: &Scanner) -> Result<(), ()> {
    match conn.execute(
        "INSERT INTO scanners (ip, ip_type, scanner_name, created_at, updated_at, last_seen_at, last_checked_at)
        VALUES (:ip, :ip_type, :scanner_name, :created_at, :updated_at, :last_seen_at, :last_checked_at)
        ON CONFLICT(ip, ip_type) DO UPDATE SET updated_at = :updated_at, last_seen_at = :last_seen_at, last_checked_at = :last_checked_at;",
        named_params! {
            ":ip": &scanner.ip,
            ":ip_type": &scanner.ip_type,
            ":scanner_name": &scanner.scanner_name,
            ":created_at": &scanner.created_at,
            ":updated_at": &scanner.updated_at,
            ":last_seen_at": &scanner.last_seen_at,
            ":last_checked_at": &scanner.last_checked_at
        },
    ) {
        Ok(_) => {
            Ok(())
        },
        Err(_) => {
            Err(())
        },
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
                .eq_case(&Name::from_str("stretchoid.com").expect("Should parse")) =>
        {
            Ok(Scanners::Strechoid)
        }
        _ => Err(()),
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
            <p><textarea name="ips"></textarea></p>
            <p><button>Scan</button></p>
        </form>
    </body>
</html>
"#;

fn handle_scan(conn: &Mutex<Connection>, request: &Request) -> Response {
    let data = try_or_400!(post_input!(request, {
        ips: String,
    }));
    rouille::Response::html(data.ips.split('\n').collect::<Vec<&str>>().join("<br>"))
}

fn handle_report(conn: &Mutex<Connection>, request: &Request) -> Response {
    let data = try_or_400!(post_input!(request, {
        ip: String,
    }));

    // We just print what was received on stdout. Of course in a real application
    // you probably want to process the data, eg. store it in a database.
    println!("Received data: {:?}", data);
    let query_address = data.ip.parse().expect("To parse");

    let client = get_dns_client();
    let ptr_result = get_ptr(query_address, client).unwrap();

    match detect_scanner(&ptr_result) {
        Ok(scanner_name) => {
            let ip_type = if data.ip.contains(':') { 6 } else { 4 };
            let scanner = Scanner {
                ip: data.ip,
                ip_type: ip_type,
                scanner_name: scanner_name.clone(),
                created_at: Utc::now().to_string(),
                updated_at: Utc::now().to_string(),
                last_seen_at: Utc::now().to_string(),
                last_checked_at: Utc::now().to_string(),
            };
            let db = conn.lock().unwrap();
            save_scanner(&db, &scanner).unwrap();
            rouille::Response::html(match scanner_name {
                Scanners::Binaryedge => format!(
                    "Reported an escaped ninja! <b>{}</a> {:?}.",
                    scanner.ip,
                    ptr_result.result.unwrap()
                ),
                Scanners::Strechoid => format!(
                    "Reported a stretchoid agent! <b>{}</a> {:?}.",
                    scanner.ip,
                    ptr_result.result.unwrap()
                ),
            })
        }

        Err(_) => rouille::Response::html(format!(
            "The IP <b>{}</a> resolved as {:?} did not match known scanners patterns.",
            data.ip, ptr_result.result
        )),
    }
}

fn handle_list_scanners(conn: &Mutex<Connection>, scanner_name: String) -> Response {
    let db = conn.lock().unwrap();
    let mut stmt = db.prepare("SELECT ip FROM scanners WHERE scanner_name = :scanner_name ORDER BY ip_type, created_at").unwrap();
    let mut rows = stmt
        .query(named_params! { ":scanner_name": scanner_name })
        .unwrap();
    let mut ips: Vec<String> = vec![];
    while let Some(row) = rows.next().unwrap() {
        ips.push(row.get(0).unwrap());
    }

    Response {
        status_code: 200,
        headers: vec![("Content-Type".into(), "text/plain; charset=utf-8".into())],
        data: ResponseBody::from_string(ips.join("\n")),
        upgrade: None,
    }
}

fn get_connection() -> Connection {
    let path = "./snow-scanner.sqlite";
    let conn = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_WRITE
            | OpenFlags::SQLITE_OPEN_CREATE
            | OpenFlags::SQLITE_OPEN_FULL_MUTEX,
    )
    .unwrap();
    conn.execute(
        "CREATE TABLE IF NOT EXISTS scanners (
            ip VARCHAR(255),
            ip_type TINYINT(1),
            scanner_name VARCHAR(255),
            created_at DATETIME,
            updated_at DATETIME,
            last_seen_at DATETIME,
            last_checked_at DATETIME,
            PRIMARY KEY (ip, ip_type)
        )",
        (), // empty list of parameters.
    )
    .unwrap();
    conn.pragma_update_and_check(None, "journal_mode", &"WAL", |_| Ok(()))
        .unwrap();
    conn
}

fn get_dns_client() -> SyncClient<TcpClientConnection> {
    let server = "1.1.1.1:53".parse().expect("To parse");
    let dns_conn =
        TcpClientConnection::with_timeout(server, std::time::Duration::new(5, 0)).unwrap();
    SyncClient::new(dns_conn)
}

fn main() -> Result<()> {
    println!("Now listening on localhost:8000");

    let conn = Mutex::new(get_connection());
    conn.lock()
        .unwrap()
        .execute("SELECT 0 WHERE 0;", named_params! {})
        .expect("Failed to initialize database");

    rouille::start_server("localhost:8000", move |request| {
        router!(request,
            (GET) (/) => {
                rouille::Response::html(FORM)
            },

            (GET) (/ping) => {
                rouille::Response::text("pong")
            },

            (POST) (/report) => {handle_report(&conn, &request)},
            (POST) (/scan) => {handle_scan(&conn, &request)},

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

            (GET) (/scanners/{scanner_name: String}) => {
                handle_list_scanners(&conn, scanner_name)
            },
            (GET) (/{api_key: String}/scanners/{scanner_name: String}) => {
                let mut mac = HmacSha256::new_from_slice(b"my secret and secure key")
                    .expect("HMAC can take key of any size");

                mac.update(b"williamdes@wdes.fr");

                println!("{}", api_key);
                let hex_key = hex::decode(&api_key).unwrap();
                // `verify_slice` will return `Ok(())` if code is correct, `Err(MacError)` otherwise
                mac.verify_slice(&hex_key).unwrap();

                if let Some(request) = request.remove_prefix(format!("/{}", api_key).as_str()) {
                    // The `match_assets` function tries to find a file whose name corresponds to the URL
                    // of the request. The second parameter (`"."`) tells where the files to look for are
                    // located.
                    // In order to avoid potential security threats, `match_assets` will never return any
                    // file outside of this directory even if the URL is for example `/../../foo.txt`.
                    let response = rouille::match_assets(&request, "../data/");

                    // If a file is found, the `match_assets` function will return a response with a 200
                    // status code and the content of the file. If no file is found, it will instead return
                    // an empty 404 response.
                    // Here we check whether if a file is found, and if so we return the response.
                    if response.is_success() {
                        return response;
                    }
                }
                rouille::Response::empty_404()
            },
            // The code block is called if none of the other blocks matches the request.
            // We return an empty response with a 404 status code.
            _ => rouille::Response::empty_404()
        )
    });
}
