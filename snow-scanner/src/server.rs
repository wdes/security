use hickory_resolver::Name;
use std::{collections::HashMap, net::IpAddr, str::FromStr};

use crate::{worker::detection::detect_scanner_from_name, DbConn, Scanner};

pub struct Server {
    pub clients: HashMap<u32, Worker>,
    pub new_scanners: HashMap<String, IpAddr>,
}

impl Server {
    pub async fn commit(&mut self, conn: &mut DbConn) -> &Server {
        for (name, query_address) in self.new_scanners.clone() {
            let scanner_name = Name::from_str(name.as_str()).unwrap();

            match detect_scanner_from_name(&scanner_name) {
                Ok(Some(scanner_type)) => {
                    match Scanner::find_or_new(
                        query_address,
                        scanner_type,
                        Some(scanner_name),
                        conn,
                    )
                    .await
                    {
                        Ok(scanner) => {
                            // Got saved
                            self.new_scanners.remove(&name);
                            info!(
                                "Saved {scanner_type}: {name} for {query_address}: {:?}",
                                scanner.ip_ptr
                            );
                        }
                        Err(err) => {
                            error!("Unable to find or new {:?}", err);
                        }
                    };
                }
                Ok(None) => {}
                Err(_) => {}
            }
        }
        self
    }
}

#[derive(Debug, Clone)]
pub struct Worker {
    pub authenticated: bool,
    pub login: Option<String>,
}

impl Worker {
    pub fn initial() -> Worker {
        info!("New worker");
        Worker {
            authenticated: false,
            login: None,
        }
    }

    pub fn is_authenticated(&self) -> bool {
        self.authenticated
    }

    pub fn authenticate(&mut self, login: String) -> &Worker {
        if self.authenticated {
            warn!(
                "Worker is already authenticated as {}",
                self.login.clone().unwrap_or("".to_string())
            );
            return self;
        } else {
            info!("Worker is now authenticated as {login}");
        }
        self.login = Some(login);
        self.authenticated = true;
        self
    }
}

/*
impl ws2::Handler for Server {
    fn on_open(&mut self, ws: &WebSocket) -> Pod {
        info!("New client: {ws}");
        let worker = Worker::initial();
        // Add the client
        self.clients.insert(ws.id(), worker);
        Ok(())
    }

    fn on_close(&mut self, ws: &WebSocket) -> Pod {
        info!("Client /quit: {ws}");
        // Drop the client
        self.clients.remove(&ws.id());
        Ok(())
    }

    fn on_message(&mut self, ws: &WebSocket, msg: String) -> Pod {
        let client = self.clients.get_mut(&ws.id());
        if client.is_none() {
            // Impossible, close in case
            return ws.close();
        }
        let worker: &mut Worker = client.unwrap();

        info!("on message: {msg}, {ws}");

        let mut worker_reply: Option<WorkerMessages> = None;
        let worker_request: WorkerMessages = msg.clone().into();

        let result = match worker_request {
            WorkerMessages::AuthenticateRequest { login } => {
                if !worker.is_authenticated() {
                    worker.authenticate(login);
                    return Ok(());
                } else {
                    error!("Already authenticated: {ws}");
                    return Ok(());
                }
            }
            WorkerMessages::ScannerFoundResponse { name, address } => {
                info!("Detected {name} for {address}");
                self.new_scanners.insert(name, address);
                Ok(())
            }
            WorkerMessages::GetWorkRequest {} => {
                worker_reply = Some(WorkerMessages::DoWorkRequest {
                    neworks: vec![Network(IpCidr::from_str("52.189.78.0/24")?)],
                });
                Ok(())
            }
            WorkerMessages::DoWorkRequest { .. } | WorkerMessages::Invalid { .. } => {
                error!("Unable to understand: {msg}, {ws}");
                // Unable to understand, close the connection
                return ws.close();
            } /*msg => {
                  error!("No implemented: {:#?}", msg);
                  Ok(())
              }*/
        };

        // it has a request to send
        if let Some(worker_reply) = worker_reply {
            let msg_string: String = worker_reply.to_string();
            match ws.send(msg_string) {
                Ok(_) => match worker_reply {
                    WorkerMessages::DoWorkRequest { .. } => {}
                    msg => error!("No implemented: {:#?}", msg),
                },
                Err(err) => error!("Error sending reply to {ws}: {err}"),
            }
        }
        result
    }
}*/
