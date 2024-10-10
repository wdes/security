use std::{env, net::IpAddr};

use chrono::{Duration, NaiveDateTime, Utc};
use cidr::IpCidr;
use detection::detect_scanner;
use dns_ptr_resolver::{get_ptr, ResolvedResult};
use log2::*;
use scanners::Scanners;
use tungstenite::stream::MaybeTlsStream;
use tungstenite::{connect, Error, Message, WebSocket};
use weighted_rs::Weight;

pub mod detection;
pub mod ip_addr;
pub mod modules;
pub mod scanners;
pub mod utils;

use crate::detection::{get_dns_client, get_dns_server_config};
use crate::modules::WorkerMessages;
use crate::utils::get_dns_rr;

#[derive(Debug, Clone)]
pub struct IpToResolve {
    pub address: IpAddr,
}

#[derive(Debug)]
pub struct Worker {
    pub authenticated: bool,
    pub tasks: Vec<IpToResolve>,
    pub last_request_for_work: Option<NaiveDateTime>,
    ws: WebSocket<MaybeTlsStream<std::net::TcpStream>>,
}

impl Into<Worker> for WebSocket<MaybeTlsStream<std::net::TcpStream>> {
    fn into(self) -> Worker {
        let wait_time = std::time::Duration::from_secs(1);
        match self.get_ref() {
            tungstenite::stream::MaybeTlsStream::Plain(stream) => stream
                .set_read_timeout(Some(wait_time))
                .expect("set_nonblocking to work"),
            tungstenite::stream::MaybeTlsStream::NativeTls(stream) => {
                stream
                    .get_ref()
                    .set_read_timeout(Some(wait_time))
                    .expect("set_nonblocking to work");
                ()
            }
            _ => unimplemented!(),
        };
        Worker {
            authenticated: false,
            tasks: vec![],
            last_request_for_work: None,
            ws: self,
        }
    }
}

impl Worker {
    pub fn wait_for_messages(&mut self) -> Result<bool, Error> {
        self.tick();
        match self.ws.read() {
            Ok(server_request) => {
                match server_request {
                    Message::Text(msg_string) => {
                        self.receive_request(msg_string.into());
                    }
                    Message::Ping(data) => {
                        let _ = self.ws.write(Message::Pong(data));
                    }
                    Message::Pong(_) => {}
                    Message::Frame(_) => {}
                    Message::Binary(_) => {}
                    Message::Close(_) => {
                        return Ok(true); // Break the processing loop
                    }
                };
                Ok(false)
            }
            Err(err) => {
                match err {
                    // Silently drop the error: Processing error: IO error: Resource temporarily unavailable (os error 11)
                    // That occurs when no messages are to be read
                    Error::Io(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => Ok(false),
                    Error::Io(ref e) if e.kind() == std::io::ErrorKind::NotConnected => Ok(true), // Break the processing loop
                    _ => Err(err),
                }
            }
        }
    }

    pub fn is_authenticated(&self) -> bool {
        self.authenticated
    }

    pub fn authenticate(&mut self, login: String) -> &Worker {
        if self.authenticated {
            warn!("Worker is already authenticated");
            return self;
        } else {
            info!("Worker is now authenticated as {login}");
        }
        self.authenticated = true;
        self
    }

    pub fn tick(&mut self) -> () {
        let mut request: Option<WorkerMessages> = None;
        if !self.is_authenticated() {
            request = Some(WorkerMessages::AuthenticateRequest {
                login: env::var("WORKER_NAME").expect("The ENV WORKER_NAME should be set"),
            });
        } else {
            if self.last_request_for_work.is_none()
                || (self.last_request_for_work.is_some()
                    && Utc::now().naive_utc()
                        > (self.last_request_for_work.unwrap() + Duration::minutes(10)))
            {
                request = Some(WorkerMessages::GetWorkRequest {});
            }
        }

        // it has a request to send
        if let Some(request) = request {
            self.send_request(request);
        }
    }

    pub fn send_request(&mut self, request: WorkerMessages) -> &Worker {
        let msg_string: String = request.to_string();
        match self.ws.send(Message::Text(msg_string)) {
            Ok(_) => {
                match request {
                    WorkerMessages::AuthenticateRequest { login } => {
                        self.authenticated = true; // Anyway, it will kick us if this is not success
                        info!("Logged in as: {login}")
                    }
                    WorkerMessages::GetWorkRequest {} => {
                        self.last_request_for_work = Some(Utc::now().naive_utc());
                        info!("Asked for work: {:?}", self.last_request_for_work)
                    }
                    msg => error!("No implemented: {:#?}", msg),
                }
            }
            Err(err) => error!("Unable to send: {err}"),
        }
        self
    }

    fn work_on_cidr(&mut self, cidr: IpCidr) {
        info!("Picking up: {cidr}");
        info!("Range, from {} to {}", cidr.first(), cidr.last());
        let addresses = cidr.iter().addresses();
        let count = addresses.count();
        let mut current = 0;
        let mut rr_dns_servers = get_dns_rr();

        for addr in addresses {
            let client = get_dns_client(&get_dns_server_config(&rr_dns_servers.next().unwrap()));
            match get_ptr(addr, client) {
                Ok(result) => match detect_scanner(&result) {
                    Ok(Some(scanner_name)) => {
                        self.report_detection(scanner_name, addr, result);
                    }
                    Ok(None) => {}

                    Err(err) => error!("Error detecting for {addr}: {:?}", err),
                },
                Err(_) => {
                    //debug!("Error processing {addr}: {err}")
                }
            };

            current += 1;
            if current % 10 == 0 {
                info!("Progress: {count}/{current}");
            }
        }
    }

    fn report_detection(&mut self, scanner_name: Scanners, addr: IpAddr, result: ResolvedResult) {
        info!("Detected {:?} for {addr}", scanner_name);
        let request = WorkerMessages::ScannerFoundResponse {
            name: result.result.unwrap().to_string(),
            address: addr,
        };
        let msg_string: String = request.to_string();
        match self.ws.send(Message::Text(msg_string)) {
            Ok(_) => {}
            Err(err) => error!("Unable to send scanner result: {err}"),
        }
    }

    pub fn receive_request(&mut self, server_request: WorkerMessages) -> &Worker {
        match server_request {
            WorkerMessages::DoWorkRequest { neworks } => {
                info!("Work request received for neworks: {:?}", neworks);
                for cidr in neworks {
                    let cidr = cidr.0;
                    self.work_on_cidr(cidr);
                }
            }
            WorkerMessages::AuthenticateRequest { .. }
            | WorkerMessages::ScannerFoundResponse { .. }
            | WorkerMessages::GetWorkRequest {}
            | WorkerMessages::Invalid { .. } => {
                error!("Unable to understand message: {:?}", server_request);
            }
        }
        self
    }
}

/*fn resolve_file(addresses: InetAddressIterator<IpAddr>, dns_servers: Vec<&str>) {


    let mut ips = vec![];
    for address in addresses {
        match IpAddr::from_str(address) {
            Ok(addr) => ips.push(IpToResolve {
                address: addr,
                server: rr.next().unwrap(),
            }),
            Err(err) => {
                eprintln!(
                    "Something went wrong while parsing the IP ({}): {}",
                    address, err
                );
                process::exit(1);
            }
        }
    }

    match rayon::ThreadPoolBuilder::new()
        .num_threads(30)
        .build_global()
    {
        Ok(r) => r,
        Err(err) => {
            eprintln!(
                "Something went wrong while building the thread pool: {}",
                err
            );
            process::exit(1);
        }
    }

    ips.into_par_iter()
        .enumerate()
        .for_each(|(_i, to_resolve)| {
            let server = NameServerConfigGroup::from_ips_clear(
                &[to_resolve.server.ip()],
                to_resolve.server.port(),
                true,
            );

            let ptr_result = get_ptr(to_resolve.address, resolver);
            match ptr_result {
                Ok(ptr) => match ptr.result {
                    Some(res) => println!("{} # {}", to_resolve.address, res),
                    None => println!("{}", to_resolve.address),
                },
                Err(err) => {
                    let two_hundred_millis = Duration::from_millis(400);
                    thread::sleep(two_hundred_millis);

                    eprintln!(
                        "[{}] Error for {} -> {}",
                        to_resolve.server, to_resolve.address, err.message
                    )
                }
            }
        });
}*/

fn main() -> () {
    let _log2 = log2::stdout()
        .module(true)
        .level(match env::var("RUST_LOG") {
            Ok(level) => level,
            Err(_) => "debug".to_string(),
        })
        .start();
    info!("Running the worker");
    let url = match env::var("WORKER_URL") {
        Ok(worker_url) => worker_url,
        Err(_) => "ws://127.0.0.1:8800".to_string(),
    };

    match connect(&url) {
        Ok((socket, response)) => {
            let connected = response.status() == 101;
            if connected {
                info!("Connected to: {url}");
            } else {
                info!("Connecting replied {}: {url}", response.status());
            }

            let mut worker: Worker = socket.into();
            loop {
                match worker.wait_for_messages() {
                    Ok(true) => {
                        error!("Stopping processing");
                        break;
                    }
                    Ok(false) => {
                        // Keep processing
                    }
                    Err(tungstenite::Error::ConnectionClosed) => {
                        error!("Stopping processing: connection closed");
                        break;
                    }
                    Err(tungstenite::Error::AlreadyClosed) => {
                        error!("Stopping processing: connection already closed");
                        break;
                    }
                    Err(err) => error!("Processing error: {err} -> {:?}", err),
                }
            }
        }
        Err(err) => error!("Unable to connect to {url}: {err}"),
    }
}
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

            let _ = conn.execute("UPDATE scan_tasks SET updated_at = :updated_at, started_at = :started_at WHERE cidr = :cidr AND task_group_id = :task_group_id",
                named_params! {
                    ":updated_at": Utc::now().naive_utc().to_string(),
                    ":started_at": Utc::now().naive_utc().to_string(),
                    ":cidr": cidr_str,
                    ":task_group_id": task_group_id,
                }).unwrap();

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
    }
});*/
