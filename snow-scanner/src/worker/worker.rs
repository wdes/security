use std::{env, net::IpAddr};

use chrono::{Duration, NaiveDateTime, Utc};
use detection::detect_scanner;
use dns_ptr_resolver::{get_ptr, ResolvedResult};
use log2::*;
use ws2::{Client, Pod, WebSocket};

pub mod detection;
pub mod modules;

use crate::detection::get_dns_client;
use crate::modules::WorkerMessages;

#[derive(Debug, Clone)]
pub struct IpToResolve {
    pub address: IpAddr,
}

#[derive(Debug, Clone)]
pub struct Worker {
    pub authenticated: bool,
    pub tasks: Vec<IpToResolve>,
    pub last_request_for_work: Option<NaiveDateTime>,
}

impl Worker {
    pub fn initial() -> Worker {
        info!("New worker");
        Worker {
            authenticated: false,
            tasks: vec![],
            last_request_for_work: None,
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

    pub fn tick(&mut self, ws_client: &Client) -> &Worker {
        let mut request: Option<WorkerMessages> = None;
        if !self.is_authenticated() {
            request = Some(WorkerMessages::AuthenticateRequest {
                login: "williamdes".to_string(),
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
            self.send_request(ws_client, request);
        }
        self
    }

    pub fn send_request(&mut self, ws_client: &Client, request: WorkerMessages) -> &Worker {
        let msg_string: String = request.to_string();
        match ws_client.send(msg_string) {
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

    pub fn receive_request(&mut self, ws: &WebSocket, server_request: WorkerMessages) -> &Worker {
        match server_request {
            WorkerMessages::DoWorkRequest { neworks } => {
                info!("Should work on: {:?}", neworks);
                for cidr in neworks {
                    let cidr = cidr.0;
                    info!("Picking up: {cidr}");
                    info!("Range, from {} to {}", cidr.first(), cidr.last());
                    let addresses = cidr.iter().addresses();
                    let count = addresses.count();
                    let mut current = 0;
                    for addr in addresses {
                        let client = get_dns_client();
                        match get_ptr(addr, client) {
                            Ok(result) => match detect_scanner(&result) {
                                Ok(Some(scanner_name)) => {
                                    info!("Detected {:?} for {addr}", scanner_name);
                                    let request = WorkerMessages::ScannerFoundResponse {
                                        name: result.result.unwrap().to_string(),
                                        address: addr,
                                    };
                                    let msg_string: String = request.to_string();
                                    match ws.send(msg_string) {
                                        Ok(_) => {}
                                        Err(err) => error!("Unable to send scanner result: {err}"),
                                    }
                                }
                                Ok(None) => {}

                                Err(err) => error!("Error detecting for {addr}: {:?}", err),
                            },
                            Err(err) => {
                                //debug!("Error processing {addr}: {err}")
                            }
                        };

                        current += 1;
                    }
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

impl ws2::Handler for Worker {
    fn on_open(&mut self, ws: &WebSocket) -> Pod {
        info!("Connected to: {ws}, starting to work");
        Ok(())
    }

    fn on_close(&mut self, ws: &WebSocket) -> Pod {
        info!("End of the work day: {ws}");
        Ok(())
    }

    fn on_message(&mut self, ws: &WebSocket, msg: String) -> Pod {
        let server_request: WorkerMessages = msg.clone().into();
        self.receive_request(ws, server_request);
        Ok(())
    }
}

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

    let mut worker = Worker::initial();
    match ws2::connect(&url) {
        Ok(mut ws_client) => {
            let connected = ws_client.is_open();
            if connected {
                info!("Connected to: {url}");
            } else {
                info!("Connecting to: {url}");
            }

            loop {
                match ws_client.process(&mut worker, 0.5) {
                    Ok(_) => {
                        worker.tick(&ws_client);
                    }
                    Err(err) => error!("Processing error: {err}"),
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
