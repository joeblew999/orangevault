use worker::*;

use crate::db::queries;
use crate::util::now_utc;

#[event(scheduled)]
pub async fn scheduled(event: ScheduledEvent, env: Env, _ctx: ScheduleContext) {
    console_error_panic_hook::set_once();

    let db = match env.d1("DB") {
        Ok(db) => db,
        Err(e) => {
            console_error!("cron: D1 binding error: {e}");
            return;
        }
    };

    match event.cron().as_str() {
        "0 */6 * * *" => purge_expired_sends(&db, &env).await,
        "0 0 * * *" => purge_trashed_ciphers(&db).await,
        other => console_log!("cron: unknown schedule {other}"),
    }
}

/// Delete sends past their deletion_date. For file sends, also remove files from R2.
async fn purge_expired_sends(db: &d1::D1Database, env: &Env) {
    let now = now_utc();

    // Find file sends to delete from R2 before removing DB rows
    match queries::find_expired_file_sends(db, &now).await {
        Ok(file_sends) => {
            if let Ok(r2) = env.bucket("FILES") {
                for send in &file_sends {
                    if let Ok(data) = serde_json::from_str::<serde_json::Value>(&send.data)
                        && let Some(file_id) = data.get("id").and_then(|v| v.as_str())
                    {
                        let key = format!("sends/{}/{file_id}", send.uuid);
                        if let Err(e) = r2.delete(&key).await {
                            console_error!("cron: failed to delete R2 key {key}: {e}");
                        }
                    }
                }
            }
        }
        Err(e) => console_error!("cron: find expired file sends: {e}"),
    }

    match queries::purge_expired_sends(db, &now).await {
        Ok(()) => console_log!("cron: purged expired sends"),
        Err(e) => console_error!("cron: purge expired sends: {e}"),
    }
}

/// Delete ciphers that have been in the trash for more than 30 days.
async fn purge_trashed_ciphers(db: &d1::D1Database) {
    let cutoff = (chrono::Utc::now() - chrono::Duration::days(30))
        .to_rfc3339_opts(chrono::SecondsFormat::Millis, true);

    match queries::purge_trashed_ciphers(db, &cutoff).await {
        Ok(()) => console_log!("cron: purged trashed ciphers older than 30 days"),
        Err(e) => console_error!("cron: purge trashed ciphers: {e}"),
    }
}
