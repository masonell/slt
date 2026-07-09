//! Host-to-runtime control commands.

use tokio::sync::mpsc;

/// Command sent by an embedding host to the client runtime.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientCommand {
    /// The underlying platform network changed.
    NetworkChanged,
    /// Stop the runtime cleanly.
    ///
    /// Cancel the runtime token as well when the stop must preempt an in-flight
    /// operation. A command-only stop is observed after the current operation
    /// completes; TCP writes remain bounded by `tcp_write_timeout`.
    Stop,
}

/// Sender side of the client command channel.
pub type ClientCommandSender = mpsc::UnboundedSender<ClientCommand>;

/// Receiver side of the client command channel.
pub type ClientCommandReceiver = mpsc::UnboundedReceiver<ClientCommand>;

/// Create a command channel for one client runtime.
#[must_use]
pub fn client_command_channel() -> (ClientCommandSender, ClientCommandReceiver) {
    mpsc::unbounded_channel()
}
