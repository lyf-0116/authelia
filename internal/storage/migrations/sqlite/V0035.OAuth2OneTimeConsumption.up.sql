-- The session expiry is encrypted so it is unavailable to the migration. Use a retention which can not expire.
INSERT INTO oauth2_request_replay (type, client_id, signature, expires_at)
SELECT 'authorize_code', '', signature, datetime('now', '+100 years')
FROM oauth2_authorization_code_session
WHERE active = FALSE OR revoked = TRUE
ON CONFLICT (type, client_id, signature) DO NOTHING;

INSERT INTO oauth2_request_replay (type, client_id, signature, expires_at)
SELECT 'pushed_authorization_request', '', signature, datetime('now', '+100 years')
FROM oauth2_par_context
WHERE revoked = TRUE
ON CONFLICT (type, client_id, signature) DO NOTHING;
