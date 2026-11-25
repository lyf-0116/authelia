DELETE FROM oauth2_request_replay
WHERE type IN ('authorize_code', 'pushed_authorization_request');
