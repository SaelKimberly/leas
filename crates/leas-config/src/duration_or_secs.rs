use std::ops::Deref;
use std::time::Duration;

use serde::Serialize;
use serde::de::{self, Deserialize, Deserializer, Visitor};
use serde::ser::Serializer;

/// A `Duration` that deserializes from either an integer (seconds) or a
/// humantime string (`"5s"`, `"1h"`, etc.). Always serializes as a humantime
/// string for forward-compatibility.
///
/// This provides backward compatibility for config files that still use raw
/// integers (the previous schema).
#[derive(Debug, Clone)]
pub struct DurationOrSecs(pub Duration);

impl Deref for DurationOrSecs {
    type Target = Duration;

    fn deref(&self) -> &Duration {
        &self.0
    }
}

impl std::ops::DerefMut for DurationOrSecs {
    fn deref_mut(&mut self) -> &mut Duration {
        &mut self.0
    }
}

impl From<Duration> for DurationOrSecs {
    fn from(d: Duration) -> Self {
        Self(d)
    }
}

impl Serialize for DurationOrSecs {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let s = humantime::format_duration(self.0).to_string();
        serializer.serialize_str(&s)
    }
}

impl<'de> Deserialize<'de> for DurationOrSecs {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct DurationOrSecsVisitor;

        impl Visitor<'_> for DurationOrSecsVisitor {
            type Value = DurationOrSecs;

            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str(
                    "a duration as integer seconds or humantime string (e.g. \"5s\", \"1h\")",
                )
            }

            fn visit_u64<E: de::Error>(self, secs: u64) -> Result<DurationOrSecs, E> {
                Ok(DurationOrSecs(Duration::from_secs(secs)))
            }

            fn visit_i64<E: de::Error>(self, secs: i64) -> Result<DurationOrSecs, E> {
                let secs = u64::try_from(secs)
                    .map_err(|_| de::Error::custom("negative duration not supported"))?;
                Ok(DurationOrSecs(Duration::from_secs(secs)))
            }

            fn visit_str<E: de::Error>(self, s: &str) -> Result<DurationOrSecs, E> {
                let d = humantime::parse_duration(s)
                    .map_err(|e| de::Error::custom(format!("invalid duration string: {e}")))?;
                Ok(DurationOrSecs(d))
            }
        }

        deserializer.deserialize_any(DurationOrSecsVisitor)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deserialize_integer_seconds() {
        let result: DurationOrSecs = serde_json::from_str("5").unwrap();
        assert_eq!(result.0, Duration::from_secs(5));
    }

    #[test]
    fn deserialize_humantime_string() {
        let result: DurationOrSecs = serde_json::from_str(r#""5s""#).unwrap();
        assert_eq!(result.0, Duration::from_secs(5));

        let result: DurationOrSecs = serde_json::from_str(r#""1h""#).unwrap();
        assert_eq!(result.0, Duration::from_hours(1));
    }

    #[test]
    fn serialize_as_string() {
        let d = DurationOrSecs(Duration::from_secs(5));
        let json = serde_json::to_string(&d).unwrap();
        assert_eq!(json, r#""5s""#);
    }

    #[test]
    fn deref_to_duration() {
        let d = DurationOrSecs(Duration::from_secs(42));
        assert_eq!(*d, Duration::from_secs(42));
    }
}
