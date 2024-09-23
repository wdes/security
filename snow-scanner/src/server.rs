use cidr::IpCidr;
use log2::*;
use std::{collections::HashMap, str::FromStr};
use ws2::{Pod, WebSocket};

use crate::worker::modules::{Network, WorkerMessages};

pub struct Server {
    pub clients: HashMap<u32, Worker>,
}

impl Server {
    pub fn cleanup(&self, _: &ws2::Server) -> &Server {
        // TODO: implement check not logged in
        &self
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
            WorkerMessages::GetWorkRequest {} => {
                worker_reply = Some(WorkerMessages::DoWorkRequest {
                    neworks: vec![Network(IpCidr::from_str("127.0.0.0/31")?)],
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
}
