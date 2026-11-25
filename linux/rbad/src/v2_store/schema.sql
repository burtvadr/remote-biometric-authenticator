-- RBA host state, schema 2. Only explicit offline initialization executes this.
PRAGMA application_id = 1380073778; -- 0x52424132 (RBA2)
PRAGMA user_version = 2;
CREATE TABLE host_meta (
    singleton INTEGER PRIMARY KEY CHECK(singleton=1),
    host_id BLOB NOT NULL CHECK(length(host_id)=16),
    clock_high INTEGER NOT NULL CHECK(clock_high>=0)
) STRICT;
CREATE TABLE principals (
    id BLOB PRIMARY KEY NOT NULL CHECK(length(id)=16),
    uid INTEGER NOT NULL CHECK(uid BETWEEN 0 AND 4294967295),
    name TEXT NOT NULL CHECK(length(name) BETWEEN 1 AND 64),
    generation BLOB NOT NULL UNIQUE CHECK(length(generation)=16),
    active INTEGER NOT NULL CHECK(active IN (0,1))
) STRICT;
CREATE UNIQUE INDEX active_uid ON principals(uid) WHERE active=1;
CREATE UNIQUE INDEX active_name ON principals(name) WHERE active=1;
CREATE TABLE credentials (
    id BLOB PRIMARY KEY NOT NULL CHECK(length(id)=16),
    owner BLOB NOT NULL REFERENCES principals(id),
    revision INTEGER NOT NULL CHECK(revision>=1),
    transport_key BLOB NOT NULL UNIQUE CHECK(length(transport_key)=65 AND substr(transport_key,1,1)=x'04'),
    biometric_key BLOB NOT NULL UNIQUE CHECK(length(biometric_key)=65 AND substr(biometric_key,1,1)=x'04'),
    transport_chain BLOB NOT NULL CHECK(length(transport_chain) BETWEEN 1 AND 65536),
    biometric_chain BLOB NOT NULL CHECK(length(biometric_chain) BETWEEN 1 AND 65536),
    attested_at INTEGER NOT NULL CHECK(attested_at>=0),
    assurance_until INTEGER NOT NULL CHECK(assurance_until>attested_at AND assurance_until-attested_at<=2592000),
    status_checked_at INTEGER NOT NULL CHECK(status_checked_at>=attested_at),
    status_until INTEGER NOT NULL CHECK(status_until>status_checked_at AND status_until-status_checked_at<=86400),
    token_hash BLOB NOT NULL UNIQUE CHECK(length(token_hash)=32),
    revoked_at INTEGER CHECK(revoked_at IS NULL OR revoked_at>=attested_at),
    retry_until INTEGER CHECK(retry_until IS NULL OR (revoked_at IS NOT NULL AND retry_until-revoked_at=2592000)),
    CHECK(transport_key<>biometric_key),
    CHECK(revoked_at IS NOT NULL OR retry_until IS NULL)
) STRICT;
-- A key may never change roles or be reused in a different credential.
CREATE TABLE key_history (
    key BLOB PRIMARY KEY NOT NULL CHECK(length(key)=65),
    credential BLOB NOT NULL REFERENCES credentials(id),
    role INTEGER NOT NULL CHECK(role IN (0,1)),
    UNIQUE(credential,role)
) STRICT;
CREATE TABLE grants (
    credential BLOB NOT NULL REFERENCES credentials(id),
    approver BLOB NOT NULL REFERENCES principals(id),
    target BLOB NOT NULL REFERENCES principals(id),
    purpose TEXT NOT NULL CHECK(purpose='authenticate'),
    service TEXT NOT NULL,
    operation TEXT NOT NULL,
    CHECK((service='rba' AND operation='authenticate') OR
          (service='sudo' AND operation='service-auth') OR
          (service='gdm' AND operation='session-auth') OR
          (service='polkit' AND operation='action-auth')),
    PRIMARY KEY(credential,approver,target,purpose,service,operation)
) STRICT;
CREATE TABLE enrollments (
    id BLOB PRIMARY KEY NOT NULL CHECK(length(id)=16),
    credential BLOB NOT NULL UNIQUE REFERENCES credentials(id),
    receipt_hash BLOB NOT NULL UNIQUE CHECK(length(receipt_hash)=32),
    offer_hash BLOB NOT NULL CHECK(length(offer_hash)=32),
    committed_at INTEGER NOT NULL CHECK(committed_at>=0)
) STRICT;
CREATE TABLE admission (
    event_id INTEGER PRIMARY KEY,
    kind INTEGER NOT NULL CHECK(kind BETWEEN 1 AND 7),
    subject BLOB NOT NULL CHECK(length(subject)=16),
    at INTEGER NOT NULL CHECK(at>=0)
) STRICT;
CREATE INDEX admission_window ON admission(kind,subject,at);
CREATE INDEX admission_expire ON admission(at);
CREATE TABLE audit_outbox (
    seq INTEGER PRIMARY KEY AUTOINCREMENT,
    kind TEXT NOT NULL CHECK(kind IN ('principal-add','principal-disable','enroll','revoke','policy','prompt','pairing','status-refresh','tombstone-cleanup','auth-success')),
    subject BLOB NOT NULL CHECK(length(subject)=16),
    at INTEGER NOT NULL CHECK(at>=0)
) STRICT;
CREATE TRIGGER principal_cap BEFORE INSERT ON principals WHEN (SELECT count(*) FROM principals)>=4096 BEGIN SELECT RAISE(ABORT,'principal capacity'); END;
CREATE TRIGGER credential_cap BEFORE INSERT ON credentials WHEN (SELECT count(*) FROM credentials)>=4096 BEGIN SELECT RAISE(ABORT,'credential capacity'); END;
CREATE TRIGGER grant_cap BEFORE INSERT ON grants WHEN (SELECT count(*) FROM grants WHERE credential=NEW.credential)>=32 BEGIN SELECT RAISE(ABORT,'grant capacity'); END;
CREATE TRIGGER grant_active BEFORE INSERT ON grants WHEN NOT EXISTS(SELECT 1 FROM credentials c JOIN principals p ON p.id=c.owner WHERE c.id=NEW.credential AND c.owner=NEW.approver AND c.revoked_at IS NULL AND p.active=1) OR NOT EXISTS(SELECT 1 FROM principals WHERE id=NEW.approver AND active=1) OR NOT EXISTS(SELECT 1 FROM principals WHERE id=NEW.target AND active=1) BEGIN SELECT RAISE(ABORT,'inactive grant subject'); END;
CREATE TRIGGER admission_cap BEFORE INSERT ON admission WHEN (SELECT count(*) FROM admission)>=4096 BEGIN SELECT RAISE(ABORT,'admission capacity'); END;
CREATE TRIGGER audit_cap BEFORE INSERT ON audit_outbox WHEN (SELECT count(*) FROM audit_outbox)>=65536 BEGIN SELECT RAISE(ABORT,'audit capacity'); END;
