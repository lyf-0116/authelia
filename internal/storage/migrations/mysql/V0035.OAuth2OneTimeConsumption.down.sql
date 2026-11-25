DELETE FROM oauth2_request_replay
WHERE type IN ('authorize_code', 'pushed_authorization_request');

ALTER TABLE oauth2_request_replay
    MODIFY COLUMN signature VARCHAR(64) NOT NULL;
