use std::sync::{Arc, Mutex};

use crate::runtime::observer::{ClientEvent, ClientObserver};

mod command_handling;
mod reconnect_backoff;
mod startup_config_validation;
mod underlying_network;

#[derive(Clone, Default)]
struct RecordingObserver {
    events: Arc<Mutex<Vec<ClientEvent>>>,
}

impl RecordingObserver {
    fn snapshot(&self) -> Vec<ClientEvent> {
        self.events.lock().unwrap().clone()
    }
}

impl ClientObserver for RecordingObserver {
    fn on_event(&self, event: &ClientEvent) {
        self.events.lock().unwrap().push(event.clone());
    }
}
