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

-- Where an address comes from (4.2): looked up once, by the block role, from
-- DB-IP Lite data (CC BY 4.0, https://db-ip.com) and kept here, so a ban can be
-- shown with its country and network owner. One row per address.
CREATE TABLE IF NOT EXISTS ip_geo (
    ip         inet        PRIMARY KEY,
    country    char(2),
    asn        bigint,
    org        text,
    looked_up_at bigint    NOT NULL
);

-- What a dashboard may see: the active bans, with who reported them and why,
-- and where they are from. NOT the log lines (jailed_ips.matched_log_line can
-- hold user names), so a read-only login is granted this view and nothing else.
CREATE OR REPLACE VIEW offenders AS
SELECT host(j.ip)                         AS address,
       j.detector_name                    AS rule,
       j.originating_service              AS service,
       j.originating_server               AS reported_by,
       to_timestamp(j.first_blocked_at)   AS first_banned,
       to_timestamp(j.last_seen_at)       AS last_seen,
       to_timestamp(j.expires_at)         AS banned_until,
       j.block_count                      AS times_banned,
       g.country                          AS country,
       g.asn                              AS asn,
       g.org                              AS network_owner
  FROM jailed_ips j
  LEFT JOIN ip_geo g ON g.ip = j.ip
 WHERE j.expires_at > extract(epoch FROM now())
   AND NOT EXISTS (SELECT 1 FROM exemptions e WHERE e.ip >>= j.ip AND e.until_at > extract(epoch FROM now()));
