#[macro_use]
extern crate rouille;

use chrono::{DateTime, Utc};
use cidr::IpCidr;
use hmac::{Hmac, Mac};
use rouille::{Request, Response, ResponseBody};
use rusqlite::types::ToSqlOutput;
use rusqlite::Error as RusqliteError;
use rusqlite::{named_params, Connection, OpenFlags, Result, ToSql};
use sha2::Sha256;
use std::str::FromStr;
use std::sync::Mutex;
use std::time::Duration;
use std::{env, fmt, thread};
use uuid7::Uuid;

use hickory_client::client::SyncClient;
use hickory_client::rr::Name;
use hickory_client::tcp::TcpClientConnection;

use dns_ptr_resolver::{get_ptr, ResolvedResult, ResolvingError};

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
    ip_ptr: Option<String>,
    created_at: DateTime<Utc>,
    updated_at: Option<DateTime<Utc>>,
    last_seen_at: Option<DateTime<Utc>>,
    last_checked_at: Option<DateTime<Utc>>,
}

#[derive(Debug)]
struct ScanTask {
    task_group_id: Uuid,
    cidr: String,
    created_by_username: String,
    created_at: DateTime<Utc>,
    updated_at: Option<DateTime<Utc>>,
    started_at: Option<DateTime<Utc>>,
    still_processing_at: Option<DateTime<Utc>>,
    ended_at: Option<DateTime<Utc>>,
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
            ":created_at": &scanner.created_at.to_string(),
            ":updated_at": serialize_dt(scanner.updated_at),
            ":last_seen_at": serialize_dt(scanner.last_seen_at),
            ":last_checked_at": serialize_dt(scanner.last_checked_at)
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

fn serialize_dt(dt: Option<DateTime<Utc>>) -> Option<String> {
    match dt {
        Some(dt) => Some(dt.to_string()),
        None => None,
    }
}

fn save_scan_task(conn: &Connection, scan_task: &ScanTask) -> Result<(), RusqliteError> {
    match conn.execute(
        "INSERT INTO scan_tasks (task_group_id, cidr, created_by_username, created_at, updated_at, started_at, ended_at, still_processing_at)
        VALUES (:task_group_id, :cidr, :created_by_username, :created_at, :updated_at, :started_at, :ended_at, :still_processing_at)
        ON CONFLICT(cidr, task_group_id) DO UPDATE SET updated_at = :updated_at, started_at = :started_at, ended_at = :ended_at, still_processing_at = :still_processing_at;",
        named_params! {
            ":task_group_id": &scan_task.task_group_id.to_string(),
            ":cidr": &scan_task.cidr,
            ":created_by_username": &scan_task.created_by_username,
            ":created_at": &scan_task.created_at.to_string(),
            ":updated_at": serialize_dt(scan_task.updated_at),
            ":started_at": serialize_dt(scan_task.started_at),
            ":ended_at": serialize_dt(scan_task.ended_at),
            ":still_processing_at": serialize_dt(scan_task.still_processing_at),
        },
    ) {
        Ok(_) => {
            Ok(())
        },
        Err(err) => Err(err),
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

fn handle_ip2(conn: &Connection, ip: String) -> Result<Scanner, Option<ResolvedResult>> {
    let query_address = ip.parse().expect(format!("To parse: {}", ip).as_str());

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
                created_at: Utc::now(),
                updated_at: None,
                last_seen_at: None,
                last_checked_at: None,
            };
            let db = conn;
            save_scanner(&db, &scanner).unwrap();
            Ok(scanner)
        }

        Err(_) => Err(Some(ptr_result)),
    }
}

fn handle_ip(conn: &Mutex<Connection>, ip: String) -> Result<Scanner, Option<ResolvedResult>> {
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
                created_at: Utc::now(),
                updated_at: None,
                last_seen_at: None,
                last_checked_at: None,
            };
            let db = conn.lock().unwrap();
            save_scanner(&db, &scanner).unwrap();
            Ok(scanner)
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

fn handle_scan(conn: &Mutex<Connection>, request: &Request) -> Response {
    let data = try_or_400!(post_input!(request, {
        username: String,
        ips: String,
    }));

    let db = conn.lock().unwrap();
    let task_group_id = uuid7::uuid7();

    for ip in data.ips.lines() {
        let scan_task = ScanTask {
            task_group_id: task_group_id,
            cidr: ip.to_string(),
            created_by_username: data.username.clone(),
            created_at: Utc::now(),
            updated_at: None,
            started_at: None,
            still_processing_at: None,
            ended_at: None,
        };
        match save_scan_task(&db, &scan_task) {
            Ok(_) => println!("Added {}", ip.to_string()),
            Err(err) => eprintln!("Not added: {:?}", err),
        }
    }

    rouille::Response::html(format!("New task added: {} !", task_group_id))
}

fn handle_report(conn: &Mutex<Connection>, request: &Request) -> Response {
    let data = try_or_400!(post_input!(request, {
        ip: String,
    }));

    match handle_ip(conn, data.ip.clone()) {
        Ok(scanner) => rouille::Response::html(match scanner.scanner_name {
            Scanners::Binaryedge => format!(
                "Reported an escaped ninja! <b>{}</a> known as {:?}.",
                scanner.ip, scanner.ip_ptr
            ),
            Scanners::Strechoid => format!(
                "Reported a stretchoid agent! <b>{}</a> known as {:?}.",
                scanner.ip, scanner.ip_ptr
            ),
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
            ip VARCHAR(255)NOT NULL,
            ip_type TINYINT(1) NOT NULL,
            scanner_name VARCHAR(255),
            ip_ptr VARCHAR(255) NULL,
            created_at DATETIME NOT NULL,
            updated_at DATETIME NULL,
            last_seen_at DATETIME NULL,
            last_checked_at DATETIME NULL,
            PRIMARY KEY (ip, ip_type)
        )",
        (), // empty list of parameters.
    )
    .unwrap();
    conn.execute(
        "CREATE TABLE IF NOT EXISTS scan_tasks (
            task_group_id VARCHAR(255)NOT NULL,
            cidr VARCHAR(255)NOT NULL,
            created_by_username VARCHAR(255)NOT NULL,
            created_at DATETIMENOT NULL,
            updated_at DATETIME NULL,
            started_at DATETIME NOT NULL,
            still_processing_at DATETIME NULL,
            ended_at DATETIME NULL,
            PRIMARY KEY (task_group_id, cidr)
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
    let server_address: String = if let Ok(env) = env::var("SERVER_ADDRESS") {
        env
    } else {
        "localhost:8000".to_string()
    };

    println!("Now listening on {}", server_address);

    let conn = Mutex::new(get_connection());
    conn.lock()
        .unwrap()
        .execute("SELECT 0 WHERE 0;", named_params! {})
        .expect("Failed to initialize database");

    thread::spawn(|| loop {
        let conn = get_connection();
        let mut stmt = conn.prepare("SELECT task_group_id, cidr FROM scan_tasks WHERE started_at = 'NULL' ORDER BY created_at ASC").unwrap();
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
                    ":updated_at": Utc::now().to_string(),
                    ":started_at": Utc::now().to_string(),
                    ":cidr": cidr_str,
                    ":task_group_id": task_group_id,
                }).unwrap();
            for addr in cidr.iter().addresses() {
                match handle_ip2(&conn, addr.to_string()) {
                    Ok(scanner) => println!("Processed {}", scanner.ip),
                    Err(_) => println!("Processed {}", addr),
                }
            }
            let _ = conn.execute("UPDATE scan_tasks SET updated_at = :updated_at, ended_at = :ended_at WHERE cidr = :cidr AND task_group_id = :task_group_id",
                named_params! {
                    ":updated_at": Utc::now().to_string(),
                    ":ended_at": Utc::now().to_string(),
                    ":cidr": cidr_str,
                    ":task_group_id": task_group_id,
                }).unwrap();
        }

        let two_hundred_millis = Duration::from_millis(500);
        thread::sleep(two_hundred_millis);
    });

    rouille::start_server(server_address, move |request| {
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
