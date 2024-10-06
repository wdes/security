use rocket::futures::{stream::Next, SinkExt, StreamExt};
use rocket_ws::{frame::CloseFrame, Message};
use std::pin::Pin;

use crate::{
    event_bus::{EventBusEvent, EventBusWriter},
    worker::modules::WorkerMessages,
};
use rocket::futures::channel::mpsc as rocket_mpsc;

pub struct WsChat {}

impl WsChat {
    pub async fn work(
        mut stream: rocket_ws::stream::DuplexStream,
        mut bus_rx: rocket::tokio::sync::broadcast::Receiver<EventBusEvent>,
        mut bus_tx: rocket_mpsc::Sender<EventBusEvent>,
        mut ws_receiver: rocket_mpsc::Receiver<rocket_ws::Message>,
    ) {
        use crate::rocket::futures::StreamExt;
        use rocket::tokio;

        let _ = bus_tx.send(rocket_ws::Message::Ping(vec![])).await;

        let mut worker = Worker::initial(&mut stream);
        let mut interval = rocket::tokio::time::interval(std::time::Duration::from_secs(60));
        loop {
            tokio::select! {
                _ = interval.tick() => {
                    // Send message every X seconds
                    if let Ok(true) = worker.tick().await {
                        break;
                    }
                }
                result = bus_rx.recv() => {
                    let message = match result {
                        Ok(message) => message,
                        Err(err) => {
                            error!("Bus error: {err}");
                            continue;
                        }
                    };
                    if let Err(err) = worker.send(message).await {
                        error!("Error sending event to Event bus WebSocket: {}", err);
                        break;
                    }
                }
                Some(message) = ws_receiver.next() => {
                    info!("Received message from other client: {:?}", message);
                    let _ = worker.send(message).await;
                },
                Ok(false) = worker.poll() => {
                    // Continue the loop
                }
                else => {
                    break;
                }
            }
        }
    }
}

pub struct Server {}

type HandleBox = Pin<
    Box<dyn std::future::Future<Output = Result<(), rocket_ws::result::Error>> + std::marker::Send>,
>;

impl Server {
    pub fn handle(
        stream: rocket_ws::stream::DuplexStream,
        bus_rx: rocket::tokio::sync::broadcast::Receiver<EventBusEvent>,
        bus_tx: rocket_mpsc::Sender<EventBusEvent>,
        ws_receiver: rocket_mpsc::Receiver<rocket_ws::Message>,
    ) -> HandleBox {
        use rocket::tokio;

        //SharedData::add_worker(tx.clone(), &shared.workers);
        //move |mut stream: ws::stream::DuplexStream| {
        Box::pin(async move {
            let work_fn = WsChat::work(
                stream,
                bus_rx,
                bus_tx,
                ws_receiver,
                //workers
            );
            tokio::spawn(work_fn);

            tokio::signal::ctrl_c().await.unwrap();
            Ok(())
        })
    }

    pub fn new() -> Server {
        Server {}
    }

    /*pub fn add_worker(tx: rocket_mpsc::Sender<Message>, workers: &Mutex<WorkersList>) -> () {
        let workers_lock = workers.try_lock();
        if let Ok(mut workers) = workers_lock {
            workers.push(tx);
            info!("Clients: {}", workers.len());
            std::mem::drop(workers);
        } else {
            error!("Unable to lock workers");
        }
    }*/

    pub fn shutdown_to_all(server: &EventBusWriter) -> () {
        let res = server.write().try_send(Message::Close(Some(CloseFrame {
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
    }

    /*pub fn send_to_all(workers: &Mutex<WorkersList>, message: &str) -> () {
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
    }*/
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
            Some(Err(_)) => {
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
                worker_reply = Some(WorkerMessages::DoWorkRequest { neworks: vec![] });
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
