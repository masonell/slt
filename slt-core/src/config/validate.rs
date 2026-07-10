//! Configuration validation helpers.

use std::time::Duration;

use super::{ConfigError, MAX_TIMEOUT, MIN_INTERVAL};

/// Validate that a ping or reconnect interval meets the runtime timer minimum.
///
/// # Errors
///
/// Returns [`ConfigError::IntervalTooSmall`] if `value` is below
/// [`MIN_INTERVAL`].
pub fn validate_interval(field: &'static str, value: Duration) -> Result<(), ConfigError> {
    if value < MIN_INTERVAL {
        return Err(ConfigError::IntervalTooSmall {
            field,
            value,
            min: MIN_INTERVAL,
        });
    }
    Ok(())
}

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
/// Returns [`ConfigError::IntervalTooSmall`] if either bound is below
/// [`MIN_INTERVAL`], or [`ConfigError::InvalidPingInterval`] if `ping_min`
/// exceeds `ping_max`.
pub fn validate_ping_interval(ping_min: Duration, ping_max: Duration) -> Result<(), ConfigError> {
    validate_interval("ping_min", ping_min)?;
    validate_interval("ping_max", ping_max)?;
    if ping_min > ping_max {
        return Err(ConfigError::InvalidPingInterval { ping_min, ping_max });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // === validate_interval tests ===

    #[test]
    fn validate_interval_accepts_minimum() {
        assert!(validate_interval("test_field", MIN_INTERVAL).is_ok());
    }

    #[test]
    fn validate_interval_rejects_zero() {
        let result = validate_interval("test_field", Duration::ZERO);
        assert!(matches!(
            result,
            Err(ConfigError::IntervalTooSmall {
                field: "test_field",
                value: Duration::ZERO,
                min: MIN_INTERVAL,
            })
        ));
    }

    #[test]
    fn validate_interval_rejects_sub_millisecond_value() {
        let value = Duration::from_micros(999);
        let result = validate_interval("test_field", value);
        assert!(matches!(
            result,
            Err(ConfigError::IntervalTooSmall {
                field: "test_field",
                value: rejected,
                min: MIN_INTERVAL,
            }) if rejected == value
        ));
    }

    // === validate_timeout tests ===

    #[test]
    fn validate_timeout_accepts_valid_value() {
        let result = validate_timeout("test_field", Duration::from_secs(30));
        assert!(result.is_ok());
    }

    #[test]
    fn validate_timeout_accepts_one_second() {
        let result = validate_timeout("test_field", Duration::from_secs(1));
        assert!(result.is_ok());
    }

    #[test]
    fn validate_timeout_accepts_max_timeout() {
        let result = validate_timeout("test_field", MAX_TIMEOUT);
        assert!(result.is_ok());
    }

    #[test]
    fn validate_timeout_rejects_zero() {
        let result = validate_timeout("test_field", Duration::ZERO);
        assert!(matches!(
            result,
            Err(ConfigError::ZeroTimeout {
                field: "test_field"
            })
        ));
    }

    #[test]
    fn validate_timeout_rejects_value_exceeding_max() {
        let value = MAX_TIMEOUT + Duration::from_secs(1);
        let result = validate_timeout("test_field", value);
        assert!(matches!(
            result,
            Err(ConfigError::TimeoutTooLarge {
                field: "test_field",
                ..
            })
        ));
    }

    // === validate_ping_interval tests ===

    #[test]
    fn validate_ping_interval_accepts_valid_range() {
        let result = validate_ping_interval(Duration::from_secs(10), Duration::from_secs(30));
        assert!(result.is_ok());
    }

    #[test]
    fn validate_ping_interval_accepts_equal_values() {
        let result = validate_ping_interval(Duration::from_secs(15), Duration::from_secs(15));
        assert!(result.is_ok());
    }

    #[test]
    fn validate_ping_interval_rejects_small_bounds() {
        for (field, ping_min, ping_max) in [
            ("ping_min", Duration::ZERO, Duration::from_secs(1)),
            ("ping_max", Duration::from_secs(1), Duration::ZERO),
        ] {
            let result = validate_ping_interval(ping_min, ping_max);
            assert!(matches!(
                result,
                Err(ConfigError::IntervalTooSmall {
                    field: rejected,
                    ..
                }) if rejected == field
            ));
        }
    }

    #[test]
    fn validate_ping_interval_rejects_min_exceeding_max() {
        let ping_min = Duration::from_secs(30);
        let ping_max = Duration::from_secs(10);
        let result = validate_ping_interval(ping_min, ping_max);
        assert!(matches!(
            result,
            Err(ConfigError::InvalidPingInterval {
                ping_min: _,
                ping_max: _
            })
        ));

        // Verify the values are captured correctly
        if let Err(ConfigError::InvalidPingInterval {
            ping_min: min,
            ping_max: max,
        }) = result
        {
            assert_eq!(min, Duration::from_secs(30));
            assert_eq!(max, Duration::from_secs(10));
        }
    }
}
