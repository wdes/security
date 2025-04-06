use std::{net::IpAddr, str::FromStr};

use crate::{DbConnection, SnowDb};

use hickory_resolver::Name;
use rocket::futures::channel::mpsc as rocket_mpsc;
use rocket::futures::StreamExt;
use rocket::tokio;
use snow_scanner_worker::detection::validate_ip;
use snow_scanner_worker::scanners::Scanners;

use crate::Scanner;

/// Handles all the raw events being streamed from balancers and parses and filters them into only the events we care about.
pub struct EventBus {
    events_rx: rocket_mpsc::Receiver<EventBusWriterEvent>,
    events_tx: rocket_mpsc::Sender<EventBusWriterEvent>,
    bus_tx: tokio::sync::broadcast::Sender<EventBusEvent>,
}

impl EventBus {
    pub fn new() -> Self {
        let (events_tx, events_rx) = rocket_mpsc::channel(100);
        let (bus_tx, _) = tokio::sync::broadcast::channel(100);
        Self {
            events_rx,
            events_tx,
            bus_tx,
        }
    }

    // db: &Connection<SnowDb>
    pub async fn run(&mut self, mut conn: DbConnection<SnowDb>) {
        info!("EventBus started");
        loop {
            tokio::select! {
                Some(event) = self.events_rx.next() => {
                    self.handle_event(event, &mut conn).await;
                }
                else => {
                    warn!("EventBus stopped");
                    break;
                }
            }
        }
    }

    async fn handle_event(&self, event: EventBusWriterEvent, db: &mut DbConnection<SnowDb>) {
        info!("Received event");
        if self.bus_tx.receiver_count() == 0 {
            return;
        }
        match event {
            EventBusWriterEvent::ScannerFoundResponse { name, address } => {
                let ip: IpAddr = address.into();
                if !validate_ip(ip) {
                    error!("Invalid IP address: {ip}");
                    return;
                }
                let name = Name::from_str(name.as_str()).unwrap();
                let scanner: Result<Scanners, String> = name.clone().try_into();

                match scanner {
                    Ok(scanner_type) => {
                        match Scanner::find_or_new(ip, scanner_type.to_owned(), Some(name), db)
                            .await
                        {
                            Ok(scanner) => {
                                let _ = scanner.save(db).await;
                            }
                            Err(err) => {
                                error!("Error find or save: {:?}", err);
                            }
                        }
                    }

                    Err(err) => {
                        error!("No name detected error: {:?}", err);
                    }
                };
            }
            EventBusWriterEvent::BroadcastMessage(msg) => match self.bus_tx.send(msg) {
                Ok(count) => {
                    info!("Event sent to {count} subscribers");
                }
                Err(err) => {
                    error!("Error sending event to subscribers: {}", err);
                }
            },
        }
    }

    pub fn subscriber(&self) -> EventBusSubscriber {
        EventBusSubscriber::new(self.bus_tx.clone())
    }

    pub fn writer(&self) -> EventBusWriter {
        EventBusWriter::new(self.events_tx.clone())
    }
}

pub type EventBusEvent = rocket_ws::Message;

/// Enables subscriptions to the event bus
pub struct EventBusSubscriber {
    bus_tx: tokio::sync::broadcast::Sender<EventBusEvent>,
}

/// Enables subscriptions to the event bus
pub struct EventBusWriter {
    bus_tx: rocket_mpsc::Sender<EventBusWriterEvent>,
}

pub enum EventBusWriterEvent {
    BroadcastMessage(rocket_ws::Message),
    ScannerFoundResponse { name: String, address: IpAddr },
}

impl EventBusWriter {
    pub fn new(bus_tx: rocket_mpsc::Sender<EventBusWriterEvent>) -> Self {
        Self { bus_tx }
    }

    pub fn write(&self) -> rocket_mpsc::Sender<EventBusWriterEvent> {
        self.bus_tx.clone()
    }
}

impl EventBusSubscriber {
    pub fn new(bus_tx: tokio::sync::broadcast::Sender<EventBusEvent>) -> Self {
        Self { bus_tx }
    }

    pub fn subscribe(&self) -> tokio::sync::broadcast::Receiver<EventBusEvent> {
        self.bus_tx.subscribe()
    }
}
