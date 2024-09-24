use actix_files::NamedFile;
use actix_web::error::ErrorInternalServerError;
use actix_web::http::header::ContentType;
use actix_web::{web, App, HttpRequest, HttpResponse, HttpServer};
use log2::*;

use chrono::{NaiveDateTime, Utc};
use diesel::deserialize::{self};
use diesel::mysql::{Mysql, MysqlValue};
use diesel::sql_types::Text;

use diesel::r2d2::ConnectionManager;
use diesel::r2d2::Pool;
use worker::detection::{detect_scanner, get_dns_client, Scanners};

use std::collections::HashMap;
use std::io::Write;
use std::path::PathBuf;
use std::{env, fmt};
use uuid::Uuid;

use serde::{Deserialize, Deserializer, Serialize};

use diesel::serialize::IsNull;
use diesel::{serialize, MysqlConnection};
use dns_ptr_resolver::{get_ptr, ResolvedResult};

pub mod models;
pub mod schema;
pub mod server;
pub mod worker;

use crate::models::*;
use crate::server::Server;

/// Short-hand for the database pool type to use throughout the app.
type DbPool = Pool<ConnectionManager<MysqlConnection>>;

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

async fn handle_ip(pool: web::Data<DbPool>, ip: String) -> Result<Scanner, Option<ResolvedResult>> {
    let query_address = ip.parse().expect("To parse");

    let ptr_result: Result<ResolvedResult, ()> = std::thread::spawn(move || {
        let client = get_dns_client();
        let ptr_result: ResolvedResult = if let Ok(res) = get_ptr(query_address, client) {
            res
        } else {
            return Err(());
        };
        Ok(ptr_result)
    })
    .join()
    .unwrap();

    if ptr_result.is_err() {
        return Err(None);
    }

    let result = ptr_result.unwrap();

    match detect_scanner(&result) {
        Ok(Some(scanner_type)) => {
            // use web::block to offload blocking Diesel queries without blocking server thread
            web::block(move || {
                // note that obtaining a connection from the pool is also potentially blocking
                let conn = &mut pool.get().unwrap();
                match Scanner::find_or_new(query_address, scanner_type, result.result, conn) {
                    Ok(scanner) => Ok(scanner),
                    Err(_) => Err(None),
                }
            })
            .await
            .unwrap()
        }
        Ok(None) => Err(None),

        Err(_) => Err(Some(result)),
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
                Ok(_) => error!("Added {}", ip.to_string()),
                Err(err) => error!("Not added: {:?}", err),
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
            Scanners::Binaryedge => match scanner.last_checked_at {
                Some(date) => format!(
                    "Reported a binaryedge ninja! <b>{}</b> known as {} since {date}.",
                    scanner.ip,
                    scanner.ip_ptr.unwrap_or("".to_string())
                ),
                None => format!(
                    "Reported a binaryedge ninja! <b>{}</b> known as {}.",
                    scanner.ip,
                    scanner.ip_ptr.unwrap_or("".to_string())
                ),
            },
            Scanners::Stretchoid => match scanner.last_checked_at {
                Some(date) => format!(
                    "Reported a stretchoid agent! <b>{}</b> known as {} since {date}.",
                    scanner.ip,
                    scanner.ip_ptr.unwrap_or("".to_string())
                ),
                None => format!(
                    "Reported a stretchoid agent! <b>{}</b> known as {}.",
                    scanner.ip,
                    scanner.ip_ptr.unwrap_or("".to_string())
                ),
            },
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

struct SecurePath {
    pub data: String,
}

impl<'de> Deserialize<'de> for SecurePath {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = <Vec<String>>::deserialize(deserializer)?;
        let k: String = s[0].to_string();
        // A-Z a-z 0-9
        // . - _
        if k.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_')
        {
            return Ok(SecurePath { data: k });
        }
        Err(serde::de::Error::custom(format!(
            "Invalid value: {}",
            k.to_string()
        )))
    }
}

async fn handle_get_collection(
    path: web::Path<(SecurePath, SecurePath)>,
    req: HttpRequest,
    static_data_dir: actix_web::web::Data<String>,
) -> actix_web::Result<HttpResponse> {
    let (vendor_name, file_name) = path.into_inner();

    let mut path: PathBuf = PathBuf::new();
    let static_data_dir: String = static_data_dir.into_inner().to_string();
    path.push(static_data_dir);
    path.push("collections");
    path.push(vendor_name.data);
    path.push(file_name.data);
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
        path.push("scanners");
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
        .max_size(5)
        .test_on_check_out(true)
        .build(manager)
        .expect("Could not build connection pool")
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
    let _log2 = log2::stdout()
        .module(false)
        .level(match env::var("RUST_LOG") {
            Ok(level) => level,
            Err(_) => "debug".to_string(),
        })
        .start();

    let server_address: String = if let Ok(env) = env::var("SERVER_ADDRESS") {
        env
    } else {
        "127.0.0.1:8000".to_string()
    };

    let worker_server_address: String = if let Ok(env) = env::var("WORKER_SERVER_ADDRESS") {
        env
    } else {
        "127.0.0.1:8800".to_string()
    };

    let db_url: String = if let Ok(env) = env::var("DB_URL") {
        env
    } else {
        error!("Missing ENV: DB_URL");
        "mysql://localhost".to_string()
    };

    let pool = get_connection(db_url.as_str());

    // note that obtaining a connection from the pool is also potentially blocking
    let conn = &mut pool.get().unwrap();
    let names = Scanner::list_names(Scanners::Stretchoid, conn);
    match names {
        Ok(names) => info!("Found {} Stretchoid scanners", names.len()),
        Err(err) => error!("Unable to get names: {}", err),
    };

    let server = HttpServer::new(move || {
        let static_data_dir: String = match env::var("STATIC_DATA_DIR") {
            Ok(val) => val,
            Err(_) => "../data/".to_string(),
        };

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
            match ws2::listen(worker_server_address.as_str()) {
                Ok(mut ws_server) => {
                    std::thread::spawn(move || {
                        let pool = get_connection(db_url.as_str());
                        // note that obtaining a connection from the pool is also potentially blocking
                        let conn = &mut pool.get().unwrap();
                        let mut ws_server_handles = Server {
                            clients: HashMap::new(),
                            new_scanners: HashMap::new(),
                        };
                        info!("Worker server is listening on: {worker_server_address}");
                        loop {
                            match ws_server.process(&mut ws_server_handles, 0.5) {
                                Ok(_) => {}
                                Err(err) => error!("Processing error: {err}"),
                            }
                            ws_server_handles.cleanup(&ws_server);
                            ws_server_handles.commit(conn);
                        }
                    });
                }
                Err(err) => error!("Unable to listen on {worker_server_address}: {err}"),
            };

            info!("Now listening on {}", server_address);
            server.run().await
        }
        Err(err) => {
            error!("Could not bind the server to {}", server_address);
            Err(err)
        }
    }
}
