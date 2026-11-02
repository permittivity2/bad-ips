-- ============================================================================
-- bad-ips shared ban list (4.0)
--
-- Idempotent: safe to apply again. Apply it as the role that should OWN the
-- tables (on the homelab fleet, badips_migrate) with search_path set to the
-- schema, so the runtime login's default privileges cover them:
--
--   SET ROLE badips_migrate; SET search_path = badips; \i schema.sql
--
-- jailed_ips keeps the 3.x shape (one row per address per reporting host),
-- so a 3.x host pointed at the same database keeps working. Times are epoch
-- seconds.
-- ============================================================================

CREATE TABLE IF NOT EXISTS jailed_ips (
    id                  bigserial    PRIMARY KEY,
    ip                  inet         NOT NULL,
    originating_server  varchar(255) NOT NULL,
    originating_service varchar(255),
    detector_name       varchar(255),
    pattern_matched     text,
    matched_log_line    text,
    first_blocked_at    bigint       NOT NULL,
    last_seen_at        bigint       NOT NULL,
    expires_at          bigint       NOT NULL,
    block_count         integer      NOT NULL DEFAULT 1,
    UNIQUE (ip, originating_server)
);

CREATE INDEX IF NOT EXISTS jailed_ips_expires_at_idx   ON jailed_ips (expires_at);
CREATE INDEX IF NOT EXISTS jailed_ips_last_seen_at_idx ON jailed_ips (last_seen_at);

-- "Do not block this address (or network) until until_at." Written by
-- `bad_ips unban`, so the next matching log line does not ban it straight back.
CREATE TABLE IF NOT EXISTS exemptions (
    id          bigserial    PRIMARY KEY,
    ip          inet         NOT NULL,
    until_at    bigint       NOT NULL,
    reason      text,
    created_by  varchar(255),
    created_at  bigint       NOT NULL
);

CREATE INDEX IF NOT EXISTS exemptions_ip_idx       ON exemptions USING gist (ip inet_ops);
CREATE INDEX IF NOT EXISTS exemptions_until_at_idx ON exemptions (until_at);
