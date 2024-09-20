use actix_files::NamedFile;
use actix_web::error::ErrorInternalServerError;
use actix_web::http::header::ContentType;
use actix_web::{web, App, HttpRequest, HttpResponse, HttpServer};

use chrono::{NaiveDateTime, Utc};
use diesel::deserialize::{self, FromSqlRow};
use diesel::mysql::{Mysql, MysqlValue};
use diesel::sql_types::Text;

use diesel::r2d2::ConnectionManager;
use diesel::r2d2::Pool;

use std::io::Write;
use std::path::PathBuf;
use std::str::FromStr;
use std::{env, fmt};
use uuid::Uuid;

use serde::{Deserialize, Deserializer, Serialize};

use hickory_client::client::SyncClient;
use hickory_client::rr::Name;
use hickory_client::tcp::TcpClientConnection;

use diesel::serialize::IsNull;
use diesel::{serialize, MysqlConnection};
use dns_ptr_resolver::{get_ptr, ResolvedResult};

pub mod models;
pub mod schema;

use crate::models::*;

/// Short-hand for the database pool type to use throughout the app.
type DbPool = Pool<ConnectionManager<MysqlConnection>>;

// Create alias for HMAC-SHA256
// type HmacSha256 = Hmac<Sha256>;

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
            "stretchoid.txt" => Ok(Scanners::Stretchoid),
            "binaryedge.txt" => Ok(Scanners::Binaryedge),
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

async fn handle_ip(pool: web::Data<DbPool>, ip: String) -> Result<Scanner, Option<ResolvedResult>> {
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

            // use web::block to offload blocking Diesel queries without blocking server thread
            web::block(move || {
                // note that obtaining a connection from the pool is also potentially blocking
                let conn = &mut pool.get().unwrap();

                match scanner.save(conn) {
                    Ok(scanner) => Ok(scanner),
                    Err(_) => Err(None),
                }
            })
            .await
            .unwrap()
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

#[derive(Serialize, Deserialize)]
pub struct ScanParams {
    username: String,
    ips: String,
}

async fn handle_scan(pool: web::Data<DbPool>, params: web::Form<ScanParams>) -> HttpResponse {
    if params.username.len() < 4 {
        return plain_contents("Invalid username".to_string());
    }

    let task_group_id: Uuid = Uuid::now_v7();

    // use web::block to offload blocking Diesel queries without blocking server thread
    let _ = web::block(move || {
        // note that obtaining a connection from the pool is also potentially blocking
        let conn = &mut pool.get().unwrap();
        for ip in params.ips.lines() {
            let scan_task = ScanTask {
                task_group_id: task_group_id.to_string(),
                cidr: ip.to_string(),
                created_by_username: params.username.clone(),
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
    })
    .await
    // map diesel query errors to a 500 error response
    .map_err(|err| ErrorInternalServerError(err));

    html_contents(format!("New task added: {} !", task_group_id))
}

#[derive(Serialize, Deserialize)]
pub struct ReportParams {
    ip: String,
}

async fn handle_report(pool: web::Data<DbPool>, params: web::Form<ReportParams>) -> HttpResponse {
    match handle_ip(pool, params.ip.clone()).await {
        Ok(scanner) => html_contents(match scanner.scanner_name {
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

        Err(ptr_result) => html_contents(format!(
            "The IP <b>{}</a> resolved as {:?} did not match known scanners patterns.",
            params.ip,
            match ptr_result {
                Some(res) => res.result,
                None => None,
            }
        )),
    }
}

async fn handle_get_collection(
    path: web::Path<(String, String)>,
    req: HttpRequest,
    static_data_dir: actix_web::web::Data<String>,
) -> actix_web::Result<HttpResponse> {
    let (vendor_name, file_name) = path.into_inner();

    let mut path: PathBuf = PathBuf::new();
    let static_data_dir: String = static_data_dir.into_inner().to_string();
    path.push(static_data_dir);
    path.push(vendor_name.to_string());
    path.push(file_name.to_string());
    match NamedFile::open(path) {
        Ok(file) => Ok(file.into_response(&req)),
        Err(err) => Ok(HttpResponse::NotFound()
            .content_type(ContentType::plaintext())
            .body(format!("File not found: {}.\n", err))),
    }
}

async fn handle_list_scanners(
    pool: web::Data<DbPool>,
    path: web::Path<Scanners>,
    req: HttpRequest,
    static_data_dir: actix_web::web::Data<String>,
) -> actix_web::Result<HttpResponse> {
    let scanner_name = path.into_inner();
    let static_data_dir: String = static_data_dir.into_inner().to_string();
    if scanner_name.is_static() {
        let mut path: PathBuf = PathBuf::new();
        path.push(static_data_dir);
        path.push(scanner_name.to_string());

        return match NamedFile::open(path) {
            Ok(file) => Ok(file.into_response(&req)),
            Err(err) => Ok(HttpResponse::NotFound()
                .content_type(ContentType::plaintext())
                .body(format!("File not found: {}.\n", err))),
        };
    }

    // use web::block to offload blocking Diesel queries without blocking server thread
    let scanners_list = web::block(move || {
        // note that obtaining a connection from the pool is also potentially blocking
        let conn = &mut pool.get().unwrap();
        match Scanner::list_names(scanner_name, conn) {
            Ok(data) => Ok(data),
            Err(err) => Err(err),
        }
    })
    .await
    // map diesel query errors to a 500 error response
    .map_err(|err| ErrorInternalServerError(err))
    .unwrap();

    if let Ok(scanners) = scanners_list {
        Ok(html_contents(scanners.join("\n")))
    } else {
        Ok(server_error("Unable to list scanners".to_string()))
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

async fn handle_list_scan_tasks(pool: web::Data<DbPool>) -> HttpResponse {
    let mut html_data: Vec<String> = vec![SCAN_TASKS_HEAD.to_string()];

    // use web::block to offload blocking Diesel queries without blocking server thread
    let scan_tasks_list = web::block(move || {
        // note that obtaining a connection from the pool is also potentially blocking
        let conn = &mut pool.get().unwrap();
        match ScanTask::list(conn) {
            Ok(data) => Ok(data),
            Err(err) => Err(err),
        }
    })
    .await
    // map diesel query errors to a 500 error response
    .map_err(|err| ErrorInternalServerError(err));

    if let Ok(scan_tasks) = scan_tasks_list.unwrap() {
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

        html_contents(html_data.join("\n"))
    } else {
        return server_error("Unable to list scan tasks".to_string());
    }
}

fn get_connection(database_url: &str) -> DbPool {
    let manager = ConnectionManager::<MysqlConnection>::new(database_url);
    // Refer to the `r2d2` documentation for more methods to use
    // when building a connection pool
    Pool::builder()
        .max_size(30)
        .test_on_check_out(true)
        .build(manager)
        .expect("Could not build connection pool")
}

fn get_dns_client() -> SyncClient<TcpClientConnection> {
    let server = "1.1.1.1:53".parse().expect("To parse");
    let dns_conn =
        TcpClientConnection::with_timeout(server, std::time::Duration::new(5, 0)).unwrap();
    SyncClient::new(dns_conn)
}

fn plain_contents(data: String) -> HttpResponse {
    HttpResponse::Ok()
        .content_type(ContentType::plaintext())
        .body(data)
}

fn html_contents(data: String) -> HttpResponse {
    HttpResponse::Ok()
        .content_type(ContentType::html())
        .body(data)
}

fn server_error(data: String) -> HttpResponse {
    HttpResponse::InternalServerError()
        .content_type(ContentType::html())
        .body(data)
}

async fn index() -> HttpResponse {
    html_contents(FORM.to_string())
}

async fn pong() -> HttpResponse {
    plain_contents("pong".to_string())
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let server_address: String = if let Ok(env) = env::var("SERVER_ADDRESS") {
        env
    } else {
        "localhost:8000".to_string()
    };

    let db_url: String = if let Ok(env) = env::var("DB_URL") {
        env
    } else {
        eprintln!("Missing ENV: DB_URL");
        "mysql://localhost".to_string()
    };

    let server = HttpServer::new(move || {
        let static_data_dir: String = match env::var("STATIC_DATA_DIR") {
            Ok(val) => val,
            Err(_) => "../data/".to_string(),
        };

        let pool = get_connection(db_url.as_str());
        App::new()
            .app_data(web::Data::new(pool.clone()))
            .app_data(actix_web::web::Data::new(static_data_dir))
            .route("/", web::get().to(index))
            .route("/ping", web::get().to(pong))
            .route("/report", web::post().to(handle_report))
            .route("/scan", web::post().to(handle_scan))
            .route("/scan/tasks", web::get().to(handle_list_scan_tasks))
            .route(
                "/scanners/{scanner_name}",
                web::get().to(handle_list_scanners),
            )
            .route(
                "/collections/{vendor_name}/{file_name}",
                web::get().to(handle_get_collection),
            )
    })
    .bind(&server_address);
    match server {
        Ok(server) => {
            println!("Now listening on {}", server_address);
            server.run().await
        }
        Err(err) => {
            eprintln!("Could not bind the server to {}", server_address);
            Err(err)
        }
    }
}
/*
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
