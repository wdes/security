use std::env;

use log2::*;
use ws2::{Pod, WebSocket};

pub mod modules;

use crate::modules::WorkerMessages;

#[derive(Debug, Clone)]
pub struct Worker {
    pub authenticated: bool,
}

impl Worker {
    pub fn initial() -> Worker {
        info!("New worker");
        Worker {
            authenticated: false,
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
        /*info!("on message: {msg}, {ws}");
        let echo = format!("echo: {msg}");
        let n = ws.send(echo);
        Ok(n?)*/
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
    let url = "ws://127.0.0.1:8800";
    let mut worker = Worker::initial();
    match ws2::connect(url) {
        Ok(mut ws_client) => {
            let connected = ws_client.is_open();
            if connected {
                info!("Connected to: {url}");
            } else {
                info!("Connecting to: {url}");
            }

            loop {
                match ws_client.process(&mut worker, 0.5) {
                    Ok(_) => {}
                    Err(err) => error!("Processing error: {err}"),
                }
                if ! worker.is_authenticated() {
                    let msg: WorkerMessages = WorkerMessages::AuthenticateRequest {
                        login: "williamdes".to_string(),
                    };
                    let msg: String = serde_json::to_string(&msg).expect("To serialize").into();
                    match ws_client.send(msg) {
                        Ok(_) => {
                            worker.authenticated = true;
                        }
                        Err(err) => error!("Unable to connect to {url}: {err}"),
                    }
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
