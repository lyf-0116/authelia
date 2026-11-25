ALTER TABLE oauth2_request_replay
    MODIFY COLUMN signature VARCHAR(255) NOT NULL;

-- The session expiry is encrypted so it is unavailable to the migration. Use a retention which can not expire.
INSERT IGNORE INTO oauth2_request_replay (type, client_id, signature, expires_at)
SELECT 'authorize_code', '', signature, DATE_ADD(CURRENT_TIMESTAMP, INTERVAL 100 YEAR)
FROM oauth2_authorization_code_session
WHERE active = FALSE OR revoked = TRUE;

INSERT IGNORE INTO oauth2_request_replay (type, client_id, signature, expires_at)
SELECT 'pushed_authorization_request', '', signature, DATE_ADD(CURRENT_TIMESTAMP, INTERVAL 100 YEAR)
FROM oauth2_par_context
WHERE revoked = TRUE;
