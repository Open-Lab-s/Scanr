use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

pub(crate) fn is_fresh(fetched_at: &str, ttl_hours: u64, now: OffsetDateTime) -> bool {
    let Ok(fetched_at) = OffsetDateTime::parse(fetched_at, &Rfc3339) else {
        return false;
    };

    let elapsed_seconds = now.unix_timestamp() - fetched_at.unix_timestamp();
    if elapsed_seconds < 0 {
        return true;
    }

    let ttl_seconds = i64::try_from(ttl_hours.saturating_mul(3600)).unwrap_or(i64::MAX);
    elapsed_seconds <= ttl_seconds
}
