# Feature 019: Rotation Scheduling

## Status: Planned
## Phase: 2 (v2.2)
## Priority: Low

## Problem

Rotations happen immediately when triggered. In production environments, rotations should happen during maintenance windows — not during peak traffic at 2pm on a Tuesday. There is no way to schedule a rotation for a specific time, such as "rotate STRIPE_KEY at 2am Sunday."

## Solution

Add scheduling support to the rotation engine. Operators define rotation schedules — one-time or recurring (cron-based). A background scheduler checks for pending rotations and executes them at the specified time. Supports maintenance windows, blackout periods, and timezone awareness.

## Implementation

### Files to Create/Modify

- `crates/pqvault-rotation-mcp/src/scheduler.rs` — Scheduling engine with cron support
- `crates/pqvault-core/src/models.rs` — ScheduledRotation struct in VaultMetadata
- `crates/pqvault-rotation-mcp/src/lib.rs` — MCP tools for schedule management
- `crates/pqvault-cli/src/main.rs` — Schedule CLI commands

### Data Model Changes

```rust
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ScheduledRotation {
    pub id: String,
    pub key_name: String,
    pub rotate_at: Option<String>,           // One-time: ISO8601
    pub cron_expr: Option<String>,           // Recurring: "0 2 * * SUN"
    pub timezone: String,                     // Default: "UTC"
    pub enabled: bool,
    pub last_run: Option<String>,
    pub last_result: Option<String>,
    pub created: String,
    pub blackout_windows: Vec<BlackoutWindow>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct BlackoutWindow {
    pub start_hour: u8,    // 0-23
    pub end_hour: u8,
    pub days: Vec<String>, // "Mon", "Tue", etc.
}
```

### MCP Tools

```rust
// Tool: rotation_schedule_create
{
    "name": "rotation_schedule_create",
    "params": {
        "key_name": "STRIPE_KEY",
        "cron": "0 2 * * SUN",         // At 2am every Sunday
        "timezone": "America/New_York"
    },
    "returns": { "schedule_id": "sched_abc123", "next_run": "2025-01-19T07:00:00Z" }
}

// Tool: rotation_schedule_list
{
    "name": "rotation_schedule_list",
    "params": {},
    "returns": { "schedules": [...] }
}
```

### CLI Commands

```bash
pqvault schedule create STRIPE_KEY --cron "0 2 * * SUN" --tz "America/New_York"
pqvault schedule create STRIPE_KEY --at "2025-02-01T02:00:00" --tz UTC
pqvault schedule list
pqvault schedule delete sched_abc123
pqvault schedule pause sched_abc123
pqvault schedule resume sched_abc123
```

## Core Implementation

```rust
// crates/pqvault-rotation-mcp/src/scheduler.rs

use cron::Schedule;
use chrono::{Utc, DateTime};
use std::str::FromStr;

pub struct RotationScheduler {
    schedules: Vec<ScheduledRotation>,
}

impl RotationScheduler {
    pub fn get_pending_rotations(&self) -> Vec<&ScheduledRotation> {
        let now = Utc::now();
        self.schedules.iter().filter(|s| {
            if !s.enabled { return false; }

            if let Some(at_str) = &s.rotate_at {
                if let Ok(at) = DateTime::parse_from_rfc3339(at_str) {
                    return now >= at.with_timezone(&Utc) && s.last_run.is_none();
                }
            }

            if let Some(cron) = &s.cron_expr {
                if let Ok(schedule) = Schedule::from_str(cron) {
                    let next = schedule.upcoming(Utc).next();
                    if let Some(next_time) = next {
                        let last_run = s.last_run.as_ref()
                            .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
                            .map(|dt| dt.with_timezone(&Utc));
                        return last_run.map(|lr| now > lr + chrono::Duration::minutes(1)).unwrap_or(true)
                            && self.is_within_window(s, &now);
                    }
                }
            }

            false
        }).collect()
    }

    fn is_within_window(&self, schedule: &ScheduledRotation, now: &DateTime<Utc>) -> bool {
        for window in &schedule.blackout_windows {
            let hour = now.hour() as u8;
            let day = now.format("%a").to_string();
            if window.days.contains(&day) && hour >= window.start_hour && hour < window.end_hour {
                return false;
            }
        }
        true
    }

    pub fn next_run_time(&self, schedule: &ScheduledRotation) -> Option<DateTime<Utc>> {
        if let Some(cron) = &schedule.cron_expr {
            Schedule::from_str(cron).ok()
                .and_then(|s| s.upcoming(Utc).next())
        } else {
            schedule.rotate_at.as_ref()
                .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
                .map(|dt| dt.with_timezone(&Utc))
        }
    }
}
```

## Dependencies

- `cron = "0.12"` — Cron expression parsing and scheduling
- Uses existing `chrono`, `uuid`
- Requires Feature 011 (Auto-Rotation Engine)

## Testing

### Unit Tests

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_one_time_schedule_triggers() {
        let past = (Utc::now() - chrono::Duration::hours(1)).to_rfc3339();
        let schedule = ScheduledRotation {
            id: "s1".into(),
            key_name: "KEY".into(),
            rotate_at: Some(past),
            cron_expr: None,
            timezone: "UTC".into(),
            enabled: true,
            last_run: None,
            last_result: None,
            created: Utc::now().to_rfc3339(),
            blackout_windows: vec![],
        };

        let scheduler = RotationScheduler { schedules: vec![schedule] };
        assert_eq!(scheduler.get_pending_rotations().len(), 1);
    }

    #[test]
    fn test_disabled_schedule_skipped() {
        let schedule = ScheduledRotation {
            enabled: false,
            ..create_test_schedule("KEY")
        };
        let scheduler = RotationScheduler { schedules: vec![schedule] };
        assert_eq!(scheduler.get_pending_rotations().len(), 0);
    }

    #[test]
    fn test_blackout_window_respected() {
        // This test creates a schedule that is in a blackout window right now
        // and verifies it's not triggered
        let current_hour = Utc::now().hour() as u8;
        let current_day = Utc::now().format("%a").to_string();

        let mut schedule = create_test_schedule("KEY");
        schedule.blackout_windows.push(BlackoutWindow {
            start_hour: current_hour,
            end_hour: current_hour + 1,
            days: vec![current_day],
        });

        let scheduler = RotationScheduler { schedules: vec![schedule] };
        assert_eq!(scheduler.get_pending_rotations().len(), 0);
    }
}
```

### Manual Verification

1. Schedule a rotation for 5 minutes from now
2. Wait and verify rotation executes at the correct time
3. Schedule a recurring rotation and verify it triggers on schedule
4. Define a blackout window and verify rotation is deferred

## Example Usage

```bash
$ pqvault schedule create STRIPE_KEY --cron "0 2 * * SUN" --tz "America/New_York"
Schedule created: sched_abc123
  Key: STRIPE_KEY
  Schedule: Every Sunday at 2:00 AM ET
  Next run: 2025-01-19T07:00:00Z (Sunday 2am ET)

$ pqvault schedule list
ID              Key              Schedule              Next Run          Last Run
sched_abc123    STRIPE_KEY       Sun 2:00 AM ET        Jan 19 2:00 AM    -
sched_def456    GITHUB_TOKEN     1st of month 3:00 AM  Feb 1 3:00 AM     Jan 1
```
