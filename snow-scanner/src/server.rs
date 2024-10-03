use cidr::IpCidr;
use hickory_resolver::Name;
use rocket::futures::{stream::Next, SinkExt, StreamExt};
use rocket_ws::{frame::CloseFrame, Message};
use std::{collections::HashMap, net::IpAddr, ops::Deref, str::FromStr, sync::Mutex};

use crate::worker::{
    detection::detect_scanner_from_name,
    modules::{Network, WorkerMessages},
};
use crate::{DbConn, Scanner};
use rocket::futures::channel::mpsc::Sender;

pub type WorkersList = Vec<Sender<Message>>;

pub struct SharedData {
    pub workers: Mutex<WorkersList>,
}

impl SharedData {
    pub fn init() -> SharedData {
        SharedData {
            workers: Mutex::new(vec![]),
        }
    }

    pub fn add_worker(tx: Sender<Message>, workers: &Mutex<WorkersList>) -> () {
        let workers_lock = workers.try_lock();
        if let Ok(mut workers) = workers_lock {
            workers.push(tx);
            info!("Clients: {}", workers.len());
            std::mem::drop(workers);
        } else {
            error!("Unable to lock workers");
        }
    }

    pub fn shutdown_to_all(workers: &Mutex<WorkersList>) -> () {
        let workers_lock = workers.try_lock();
        if let Ok(ref workers) = workers_lock {
            workers.iter().for_each(|tx| {
                let res = tx.clone().try_send(Message::Close(Some(CloseFrame {
                    code: rocket_ws::frame::CloseCode::Away,
                    reason: "Server stop".into(),
                })));
                match res {
                    Ok(_) => {
                        info!("Worker did receive stop signal.");
                    }
                    Err(err) => {
                        error!("Send error: {err}");
                    }
                };
            });
            info!("Currently {} workers online.", workers.len());
            std::mem::drop(workers_lock);
        } else {
            error!("Unable to lock workers");
        }
    }

    pub fn send_to_all(workers: &Mutex<WorkersList>, message: &str) -> () {
        let workers_lock = workers.try_lock();
        if let Ok(ref workers) = workers_lock {
            workers.iter().for_each(|tx| {
                let res = tx.clone().try_send(Message::Text(message.to_string()));
                match res {
                    Ok(_) => {
                        info!("Message sent to worker !");
                    }
                    Err(err) => {
                        error!("Send error: {err}");
                    }
                };
            });
            info!("Currently {} workers online.", workers.len());
            std::mem::drop(workers_lock);
        } else {
            error!("Unable to lock workers");
        }
    }
}

pub struct Server {
    pub clients: HashMap<u32, String>,
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

pub struct Worker<'a> {
    authenticated: bool,
    login: Option<String>,
    stream: &'a mut rocket_ws::stream::DuplexStream,
}

impl<'a> Worker<'a> {
    pub fn initial(stream: &mut rocket_ws::stream::DuplexStream) -> Worker {
        info!("New worker");
        Worker {
            authenticated: false,
            login: None,
            stream,
        }
    }

    pub async fn send(&mut self, msg: Message) -> Result<(), rocket_ws::result::Error> {
        self.stream.send(msg).await
    }

    pub fn next(&mut self) -> Next<'_, rocket_ws::stream::DuplexStream> {
        self.stream.next()
    }

    pub async fn tick(&mut self) -> Result<bool, ()> {
        match self.send(rocket_ws::Message::Ping(vec![])).await {
            Ok(_) => Ok(false),
            Err(err) => {
                error!("Processing error: {err}");
                Ok(true) // Break processing loop
            }
        }
    }

    pub async fn poll(&mut self) -> Result<bool, ()> {
        let message = self.next();

        match message.await {
            Some(Ok(message)) => {
                match message {
                    rocket_ws::Message::Text(_) => match self.on_message(&message).await {
                        Ok(_) => {}
                        Err(err) => error!("Processing error: {err}"),
                    },
                    rocket_ws::Message::Binary(data) => {
                        // Handle Binary message
                        info!("Received Binary message: {:?}", data);
                    }
                    rocket_ws::Message::Close(close_frame) => {
                        // Handle Close message
                        info!("Received Close message: {:?}", close_frame);
                        let close_frame = rocket_ws::frame::CloseFrame {
                            code: rocket_ws::frame::CloseCode::Normal,
                            reason: "Client disconected".to_string().into(),
                        };
                        let _ = self.stream.close(Some(close_frame)).await;
                        return Ok(true); // Break processing loop
                    }
                    rocket_ws::Message::Ping(ping_data) => {
                        match self.send(rocket_ws::Message::Pong(ping_data)).await {
                            Ok(_) => {}
                            Err(err) => error!("Processing error: {err}"),
                        }
                    }
                    rocket_ws::Message::Pong(pong_data) => {
                        // Handle Pong message
                        info!("Received Pong message: {:?}", pong_data);
                    }
                    _ => {
                        info!("Received other message: {:?}", message);
                    }
                };
                Ok(false)
            }
            Some(Err(err)) => {
                info!("Connection closed");
                let close_frame = rocket_ws::frame::CloseFrame {
                    code: rocket_ws::frame::CloseCode::Normal,
                    reason: "Client disconected".to_string().into(),
                };
                let _ = self.stream.close(Some(close_frame)).await;
                // The connection is closed by the client
                Ok(true) // Break processing loop
            }
            None => Ok(false),
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

    pub async fn on_message(&mut self, msg: &Message) -> Result<(), String> {
        info!("on message: {msg}");

        let mut worker_reply: Option<WorkerMessages> = None;
        let worker_request: WorkerMessages = match msg.clone().try_into() {
            Ok(data) => data,
            Err(err) => return Err(err),
        };

        let result = match worker_request {
            WorkerMessages::AuthenticateRequest { login } => {
                if !self.is_authenticated() {
                    self.authenticate(login);
                    return Ok(());
                } else {
                    error!("Already authenticated");
                    return Ok(());
                }
            }
            WorkerMessages::ScannerFoundResponse { name, address } => {
                info!("Detected {name} for {address}");
                //self.new_scanners.insert(name, address);
                Ok(())
            }
            WorkerMessages::GetWorkRequest {} => {
                let net = IpCidr::from_str("52.189.78.0/24").unwrap();
                worker_reply = Some(WorkerMessages::DoWorkRequest {
                    neworks: vec![Network(net)],
                });
                Ok(())
            }
            WorkerMessages::DoWorkRequest { .. } | WorkerMessages::Invalid { .. } => {
                error!("Unable to understand: {msg}");
                // Unable to understand, close the connection
                //return ws.close();
                Err("Unable to understand: {msg}}")
            } /*msg => {
                  error!("No implemented: {:#?}", msg);
                  Ok(())
              }*/
        };

        // it has a request to send
        if let Some(worker_reply) = worker_reply {
            let msg_string: String = worker_reply.to_string();
            match self.send(rocket_ws::Message::Text(msg_string)).await {
                Ok(_) => match worker_reply {
                    WorkerMessages::DoWorkRequest { .. } => {}
                    msg => error!("No implemented: {:#?}", msg),
                },
                Err(err) => error!("Error sending reply: {err}"),
            }
        }
        Ok(result?)
    }
}
