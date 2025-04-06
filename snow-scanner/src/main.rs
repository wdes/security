use chrono::{NaiveDateTime, Utc};

#[macro_use]
extern crate rocket;

use cidr::IpCidr;
use event_bus::{EventBusSubscriber, EventBusWriter, EventBusWriterEvent};
use rocket::{
    fairing::AdHoc,
    form::FromFormField,
    futures::SinkExt,
    http::Status,
    request::{FromParam, FromRequest, Outcome, Request},
    trace::error,
    Rocket, State,
};
use rocket_db_pools::{
    rocket::{
        figment::{
            util::map,
            value::{Map, Value},
        },
        form::Form,
        fs::NamedFile,
        Responder,
    },
    Connection, Pool,
};

use rocket_db_pools::diesel::MysqlPool;
use rocket_db_pools::Database;
use rocket_ws::WebSocket;
use server::Server;
use weighted_rs::Weight;

use snow_scanner_worker::detection::{get_dns_client, get_dns_server_config, validate_ip};
use snow_scanner_worker::modules::{Network, WorkerMessages};
use snow_scanner_worker::scanners::ScannerMethods;
use snow_scanner_worker::scanners::Scanners;
use snow_scanner_worker::utils::get_dns_rr;

use std::net::SocketAddr;
use std::{
    env,
    net::IpAddr,
    ops::{Deref, DerefMut},
};
use std::{path::PathBuf, str::FromStr};
use uuid::Uuid;

use serde::{Deserialize, Serialize};

use dns_ptr_resolver::{get_ptr, ResolvedResult};

pub mod event_bus;
pub mod models;
pub mod schema;
pub mod server;

use crate::models::*;

#[derive(Database, Clone)]
#[database("snow_scanner_db")]
pub struct SnowDb(MysqlPool);

pub type ReqDbConn = Connection<SnowDb>;
pub type DbConn = DbConnection<SnowDb>;

#[rocket::async_trait]
impl<'r, D: Database> FromRequest<'r> for DbConnection<D> {
    type Error = Option<<D::Pool as Pool>::Error>;

    async fn from_request(req: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        match D::fetch(req.rocket()) {
            Some(db) => match db.get().await {
                Ok(conn) => Outcome::Success(DbConnection(conn)),
                Err(e) => Outcome::Error((Status::ServiceUnavailable, Some(e))),
            },
            None => Outcome::Error((Status::InternalServerError, None)),
        }
    }
}

pub struct DbConnection<D: Database>(pub <D::Pool as Pool>::Connection);

impl<D: Database> Deref for DbConnection<D> {
    type Target = <D::Pool as Pool>::Connection;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<D: Database> DerefMut for DbConnection<D> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

#[derive(serde::Deserialize, Clone)]
struct SafeIpAddr {
    pub addr: IpAddr,
}

impl FromFormField<'_> for SafeIpAddr {
    fn from_value(field: rocket::form::ValueField<'_>) -> rocket::form::Result<'_, Self> {
        let ip = field.value;
        let query_address = IpAddr::from_str(ip);
        match query_address {
            Ok(ip) => {
                if !validate_ip(ip) {
                    return Err(rocket::form::Error::validation(format!(
                        "Invalid IP address: {ip}"
                    ))
                    .into());
                }
                Ok(SafeIpAddr { addr: ip })
            }
            Err(err) => Err(rocket::form::Error::validation(format!("Invalid IP: {err}")).into()),
        }
    }
}

async fn handle_ip(
    query_address: IpAddr,
) -> Result<(IpAddr, Option<Scanners>, ResolvedResult), String> {
    let ptr_result: Result<ResolvedResult, String> = std::thread::spawn(move || {
        let mut rr_dns_servers = get_dns_rr();
        let client = get_dns_client(&get_dns_server_config(&rr_dns_servers.next().unwrap()));
        let ptr_result: ResolvedResult = if let Ok(res) = get_ptr(query_address, client) {
            res
        } else {
            return Err("Resolving error".to_string());
        };
        Ok(ptr_result)
    })
    .join()
    .unwrap();

    match ptr_result {
        Ok(result) => {
            let scanner: Result<Scanners, String> = result.query.clone().try_into();

            match scanner {
                Ok(scanner_type) => {
                    if !validate_ip(query_address) {
                        error!("Invalid IP address: {query_address}");
                        return Err("".to_string());
                    }
                    Ok((query_address, Some(scanner_type), result))
                }
                Err(err) => Err(err),
            }
        }
        Err(err) => Err(err),
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

#[derive(FromForm, Serialize, Deserialize)]
pub struct ScanParams<'r> {
    username: &'r str,
    ips: &'r str,
}

#[derive(Responder)]
enum MultiReply {
    #[response(status = 500, content_type = "text")]
    Error(ServerError),
    #[response(status = 422)]
    FormError(PlainText),
    #[response(status = 422)]
    HtmlFormError(HtmlContents),
    #[response(status = 404)]
    NotFound(String),
    #[response(status = 200)]
    Content(HtmlContents),
    #[response(status = 200)]
    TextContent(PlainText),
    #[response(status = 200)]
    FileContents(NamedFile),
}

#[post("/scan", data = "<form>")]
async fn handle_scan(
    mut db: DbConn,
    form: Form<ScanParams<'_>>,
    event_bus_writer: &State<EventBusWriter>,
) -> MultiReply {
    if form.username.len() < 4 {
        return MultiReply::FormError(PlainText("Invalid username".to_string()));
    }

    let mut cidrs: Vec<IpCidr> = vec![];

    for line in form.ips.lines() {
        cidrs.push(match IpCidr::from_str(line.trim()) {
            Ok(data) => data,
            Err(err) => {
                return MultiReply::FormError(PlainText(format!("Invalid value: {line}: {err}")))
            }
        });
    }

    let task_group_id: Uuid = Uuid::now_v7();

    for cidr in cidrs {
        let scan_task = ScanTask {
            task_group_id: task_group_id.to_string(),
            cidr: cidr.to_string(),
            created_by_username: form.username.to_string(),
            created_at: Utc::now().naive_utc(),
            updated_at: None,
            started_at: None,
            still_processing_at: None,
            ended_at: None,
        };
        let mut bus_tx = event_bus_writer.write();
        match scan_task.save(&mut db).await {
            Ok(_) => {
                info!("Added {}", cidr.to_string());

                let msg = EventBusWriterEvent::BroadcastMessage(
                    WorkerMessages::DoWorkRequest {
                        networks: vec![Network(cidr)],
                    }
                    .into(),
                );

                let _ = bus_tx.send(msg).await;
            }
            Err(err) => error!("Not added: {:?}", err),
        }
    }

    MultiReply::Content(HtmlContents(format!("New task added: {} !", task_group_id)))
}

#[derive(FromForm, Deserialize)]
pub struct ReportParams {
    ip: SafeIpAddr,
}

fn reply_contents_for_scanner_found(scanner: Scanner) -> HtmlContents {
    HtmlContents(match scanner.last_checked_at {
        Some(date) => format!(
            "Reported a {}! <b>{}</b> known as {} since {date}.",
            scanner.scanner_name.funny_name(),
            scanner.ip,
            scanner.ip_ptr.unwrap_or("".to_string())
        ),
        None => format!(
            "Reported a {}! <b>{}</b> known as {}.",
            scanner.scanner_name.funny_name(),
            scanner.ip,
            scanner.ip_ptr.unwrap_or("".to_string())
        ),
    })
}

#[post("/report", data = "<form>")]
async fn handle_report(mut db: DbConn, form: Form<ReportParams>) -> MultiReply {
    match handle_ip(form.ip.addr).await {
        Ok((query_address, scanner_type, result)) => match scanner_type {
            Some(scanner_type) => match Scanner::find_or_new(
                query_address,
                scanner_type,
                result.result.clone(),
                &mut db,
            )
            .await
            {
                Ok(scanner) => MultiReply::Content(reply_contents_for_scanner_found(scanner)),
                Err(err) => MultiReply::Error(ServerError(format!(
                    "The IP {} resolved as {} could not be saved, server error: {err}.",
                    form.ip.addr,
                    match result.result {
                        Some(res) => res.to_string(),
                        None => "No value".to_string(),
                    }
                ))),
            },
            None => MultiReply::HtmlFormError(HtmlContents(format!(
                "The IP <b>{}</a> resolved as {:?} did not match known scanners patterns.",
                form.ip.addr,
                match result.result {
                    Some(res) => res.to_string(),
                    None => "No value".to_string(),
                }
            ))),
        },

        Err(_) => MultiReply::Error(ServerError(format!(
            "The IP <b>{}</a> did encounter en error at resolve time.",
            form.ip.addr
        ))),
    }
}

struct SecurePath {
    pub data: String,
}

impl FromParam<'_> for SecurePath {
    type Error = String;

    fn from_param(param: &'_ str) -> Result<Self, Self::Error> {
        // A-Z a-z 0-9
        // . - _
        if param
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_')
        {
            return Ok(SecurePath {
                data: param.to_string(),
            });
        }
        Err(format!(
            "Invalid path value (forbidden chars): {}",
            param.to_string()
        ))
    }
}

#[get("/collections/<vendor_name>/<file_name>")]
async fn handle_get_collection(
    vendor_name: SecurePath,
    file_name: SecurePath,
    app_configs: &State<AppConfigs>,
) -> MultiReply {
    let mut path: PathBuf = PathBuf::new();
    let static_data_dir: String = app_configs.static_data_dir.clone();
    path.push(static_data_dir);
    path.push("collections");
    path.push(vendor_name.data);
    path.push(file_name.data);
    match NamedFile::open(path).await {
        Ok(file) => MultiReply::FileContents(file),
        Err(err) => MultiReply::NotFound(err.to_string()),
    }
}

#[get("/scanners/<scanner_name>")]
async fn handle_list_scanners(
    mut db: DbConn,
    scanner_name: Scanners,
    app_configs: &State<AppConfigs>,
) -> MultiReply {
    let static_data_dir: String = app_configs.static_data_dir.clone();
    if scanner_name.is_static() {
        let mut path: PathBuf = PathBuf::new();
        path.push(static_data_dir);
        path.push("scanners");
        path.push(
            scanner_name
                .static_file_name()
                .expect("Static files should have a static file name"),
        );

        return match NamedFile::open(path).await {
            Ok(file) => MultiReply::FileContents(file),
            Err(err) => MultiReply::NotFound(err.to_string()),
        };
    }

    let scanners_list = match Scanner::list_names(scanner_name, &mut db).await {
        Ok(data) => Ok(data),
        Err(err) => Err(err),
    };

    if let Ok(scanners) = scanners_list {
        MultiReply::TextContent(PlainText(scanners.join("\n")))
    } else {
        MultiReply::Error(ServerError("Unable to list scanners".to_string()))
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

#[get("/scan/tasks")]
async fn handle_list_scan_tasks(mut db: DbConn) -> MultiReply {
    let mut html_data: Vec<String> = vec![SCAN_TASKS_HEAD.to_string()];

    let scan_tasks_list = match ScanTask::list(&mut db).await {
        Ok(data) => Ok(data),
        Err(err) => Err(err),
    };

    if let Ok(scan_tasks) = scan_tasks_list {
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

        MultiReply::Content(HtmlContents(html_data.join("\n")))
    } else {
        return MultiReply::Error(ServerError("Unable to list scan tasks".to_string()));
    }
}

#[derive(Responder)]
#[response(status = 200, content_type = "text")]
pub struct PlainText(String);

#[derive(Responder)]
#[response(status = 200, content_type = "html")]
pub struct HtmlContents(String);

#[derive(Responder)]
#[response(status = 500, content_type = "html")]
pub struct ServerError(String);

#[get("/")]
async fn index() -> HtmlContents {
    HtmlContents(FORM.to_string())
}

#[get("/ping")]
async fn pong() -> PlainText {
    PlainText("pong".to_string())
}

#[get("/ws")]
pub async fn ws(
    ws: WebSocket,
    event_bus: &State<EventBusSubscriber>,
    event_bus_writer: &State<EventBusWriter>,
) -> rocket_ws::Channel<'static> {
    use rocket::futures::channel::mpsc as rocket_mpsc;

    let (_, ws_receiver) = rocket_mpsc::channel::<rocket_ws::Message>(1);
    let bus_rx = event_bus.subscribe();
    let bus_tx = event_bus_writer.write();
    let channel: rocket_ws::Channel =
        ws.channel(|stream| Server::handle(stream, bus_rx, bus_tx, ws_receiver));

    channel
}

struct AppConfigs {
    static_data_dir: String,
}

async fn report_counts<'a>(rocket: Rocket<rocket::Build>) -> Rocket<rocket::Build> {
    let conn = SnowDb::fetch(&rocket)
        .expect("Failed to get DB connection")
        .clone()
        .get()
        .await
        .unwrap_or_else(|e| {
            span_error!("failed to connect to MySQL database" => error!("{e}"));
            panic!("aborting launch");
        });
    match Scanner::list_names(Scanners::Stretchoid, &mut DbConnection(conn)).await {
        Ok(d) => info!("Found {} Stretchoid scanners", d.len()),
        Err(err) => error!("Unable to fetch Stretchoid scanners: {err}"),
    }

    rocket
}

#[rocket::main]
async fn main() -> Result<(), rocket::Error> {
    let server_address: SocketAddr = if let Ok(env) = env::var("SERVER_ADDRESS") {
        env.parse()
            .expect("The ENV SERVER_ADDRESS should be a valid socket address (address:port)")
    } else {
        "127.0.0.1:8000"
            .parse()
            .expect("The default address should be valid")
    };

    let static_data_dir: String = match env::var("STATIC_DATA_DIR") {
        Ok(val) => val,
        Err(_) => "../data/".to_string(),
    };

    let db_url: String = if let Ok(env) = env::var("DB_URL") {
        env
    } else {
        error!("Missing ENV: DB_URL");
        "mysql://localhost".to_string()
    };

    let db: Map<_, Value> = map! {
        "url" => db_url.into(),
        "pool_size" => 10.into(),
        "timeout" => 5.into(),
    };

    let config_figment = rocket::Config::figment()
        .merge(("address", server_address.ip().to_string()))
        .merge(("port", server_address.port()))
        .merge(("databases", map!["snow_scanner_db" => db]));

    let mut event_bus = event_bus::EventBus::new();
    let event_subscriber = event_bus.subscriber();
    let event_writer = event_bus.writer();

    let _ = rocket::custom(config_figment)
        .attach(SnowDb::init())
        .attach(AdHoc::on_ignite("Report counts", report_counts))
        .attach(AdHoc::on_shutdown("Close Websockets", |r| {
            Box::pin(async move {
                if let Some(writer) = r.state::<EventBusWriter>() {
                    Server::shutdown_to_all(writer);
                }
            })
        }))
        .attach(AdHoc::on_liftoff(
            "Run websocket client manager",
            move |r| {
                Box::pin(async move {
                    let conn = SnowDb::fetch(r)
                        .expect("Failed to get DB connection")
                        .clone()
                        .get()
                        .await
                        .unwrap_or_else(|e| {
                            span_error!("failed to connect to MySQL database" => error!("{e}"));
                            panic!("aborting launch");
                        });
                    rocket::tokio::spawn(async move {
                        event_bus.run(DbConnection(conn)).await;
                    });
                })
            },
        ))
        .manage(AppConfigs { static_data_dir })
        .manage(event_subscriber)
        .manage(event_writer)
        .mount(
            "/",
            routes![
                index,
                pong,
                handle_report,
                handle_scan,
                handle_list_scan_tasks,
                handle_list_scanners,
                handle_get_collection,
                ws,
            ],
        )
        .launch()
        .await;
    Ok(())
}

#[cfg(test)]
mod test {
    use super::*;
    use hickory_resolver::{
        config::{NameServerConfigGroup, ResolverConfig, ResolverOpts},
        Name, Resolver,
    };
    use std::time::Duration;

    #[test]
    fn test_get_ptr() {
        let server = NameServerConfigGroup::google();
        let config = ResolverConfig::from_parts(None, vec![], server);
        let mut options = ResolverOpts::default();
        options.timeout = Duration::from_secs(5);
        options.attempts = 1; // One try

        let resolver = Resolver::new(config, options).unwrap();

        let query_address = "8.8.8.8".parse().expect("To parse");

        assert_eq!(
            get_ptr(query_address, resolver).unwrap(),
            ResolvedResult {
                query: Name::from_str_relaxed("8.8.8.8.in-addr.arpa.").unwrap(),
                result: Some(Name::from_str_relaxed("dns.google.").unwrap()),
                error: None,
            }
        );
    }
}
