//! Default configuration values.

use std::time::Duration;

/// Default minimum ping interval.
pub const DEFAULT_PING_MIN: Duration = Duration::from_secs(10);

/// Default maximum ping interval.
pub const DEFAULT_PING_MAX: Duration = Duration::from_secs(30);

/// Default authentication timeout.
pub const DEFAULT_AUTH_TIMEOUT: Duration = Duration::from_secs(10);

/// Default idle timeout.
pub const DEFAULT_IDLE_TIMEOUT: Duration = Duration::from_mins(5);

/// Default UDP-QSP registration timeout (client only).
pub const DEFAULT_REGISTER_TIMEOUT: Duration = Duration::from_secs(10);

/// Default minimum reconnect backoff delay (client only).
pub const DEFAULT_RECONNECT_MIN: Duration = Duration::from_millis(200);

/// Default maximum reconnect backoff delay (client only).
pub const DEFAULT_RECONNECT_MAX: Duration = Duration::from_secs(5);

/// Returns the default minimum ping interval.
#[must_use]
pub const fn default_ping_min() -> Duration {
    DEFAULT_PING_MIN
}

/// Returns the default maximum ping interval.
#[must_use]
pub const fn default_ping_max() -> Duration {
    DEFAULT_PING_MAX
}

/// Returns the default authentication timeout.
#[must_use]
pub const fn default_auth_timeout() -> Duration {
    DEFAULT_AUTH_TIMEOUT
}

/// Returns the default idle timeout.
#[must_use]
pub const fn default_idle_timeout() -> Duration {
    DEFAULT_IDLE_TIMEOUT
}

/// Returns the default UDP-QSP registration timeout (client only).
#[must_use]
pub const fn default_register_timeout() -> Duration {
    DEFAULT_REGISTER_TIMEOUT
}

/// Returns the default minimum reconnect backoff delay (client only).
#[must_use]
pub const fn default_reconnect_min() -> Duration {
    DEFAULT_RECONNECT_MIN
}

/// Returns the default maximum reconnect backoff delay (client only).
#[must_use]
pub const fn default_reconnect_max() -> Duration {
    DEFAULT_RECONNECT_MAX
}
