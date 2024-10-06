use rocket::futures::channel::mpsc as rocket_mpsc;
use rocket::futures::StreamExt;
use rocket::tokio;

/// Handles all the raw events being streamed from balancers and parses and filters them into only the events we care about.
pub struct EventBus {
    events_rx: rocket_mpsc::Receiver<rocket_ws::Message>,
    events_tx: rocket_mpsc::Sender<rocket_ws::Message>,
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

    pub async fn run(&mut self) {
        info!("EventBus started");
        loop {
            tokio::select! {
                Some(event) = self.events_rx.next() => {
                    info!("EventBus received: {event}");
                    self.handle_event(event);
                }
                else => {
                    warn!("EventBus stopped");
                    break;
                }
            }
        }
    }

    fn handle_event(&self, event: rocket_ws::Message) {
        info!("Received event: {}", event);
        if self.bus_tx.receiver_count() == 0 {
            return;
        }
        match self.bus_tx.send(event) {
            Ok(count) => {
                info!("Event sent to {count} subscribers");
            }
            Err(err) => {
                error!("Error sending event to subscribers: {}", err);
            }
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
    bus_tx: rocket_mpsc::Sender<EventBusEvent>,
}

impl EventBusWriter {
    pub fn new(bus_tx: rocket_mpsc::Sender<EventBusEvent>) -> Self {
        Self { bus_tx }
    }

    pub fn write(&self) -> rocket_mpsc::Sender<EventBusEvent> {
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
