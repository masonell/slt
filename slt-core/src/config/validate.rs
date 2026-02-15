//! Configuration validation helpers.

use std::time::Duration;

use super::{ConfigError, MAX_TIMEOUT};

/// Validate a timeout field is non-zero and within maximum.
///
/// # Errors
///
/// Returns [`ConfigError::ZeroTimeout`] if `value` is zero, or
/// [`ConfigError::TimeoutTooLarge`] if `value` exceeds `MAX_TIMEOUT`.
pub fn validate_timeout(field: &'static str, value: Duration) -> Result<(), ConfigError> {
    if value.is_zero() {
        return Err(ConfigError::ZeroTimeout { field });
    }
    if value > MAX_TIMEOUT {
        return Err(ConfigError::TimeoutTooLarge {
            field,
            value,
            max: MAX_TIMEOUT,
        });
    }
    Ok(())
}

/// Validate ping interval range.
///
/// # Errors
///
/// Returns [`ConfigError::InvalidPingInterval`] if `ping_min` exceeds `ping_max`.
pub fn validate_ping_interval(ping_min: Duration, ping_max: Duration) -> Result<(), ConfigError> {
    if ping_min > ping_max {
        return Err(ConfigError::InvalidPingInterval { ping_min, ping_max });
    }
    Ok(())
}
