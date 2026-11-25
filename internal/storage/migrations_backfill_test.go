// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package storage

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/authelia/authelia/v4/internal/configuration/schema"
	"github.com/authelia/authelia/v4/internal/model"
)

func TestSchemaMigrateBackfillsRefreshTokenAccessSignature(t *testing.T) {
	testCases := []struct {
		name      string
		signature string
		expected  string
	}{
		{"ShouldPairTheOnlyUnrevokedAccessToken", "rt_a2", "at_a2"},
		{"ShouldNotPairWhenAmbiguous", "rt_b1", ""},
		{"ShouldNotPairWhenNoUnrevokedAccessToken", "rt_c1", ""},
		{"ShouldNotPairARevokedRefreshToken", "rt_a1", ""},
	}

	config := &schema.Configuration{
		Storage: schema.Storage{
			EncryptionKey: "authelia-test-key-not-a-secret-authelia-test-key-not-a-secret",
			Local:         &schema.StorageLocal{Path: filepath.Join(t.TempDir(), "db.sqlite3")},
		},
	}

	ctx := context.Background()

	provider, err := NewSQLiteProvider(config)

	require.NoError(t, err)

	t.Cleanup(func() {
		_ = provider.Close()
	})

	require.NoError(t, provider.SchemaMigrate(ctx, true, 26))

	seedAccess := `INSERT INTO oauth2_access_token_session (challenge_id, request_id, client_id, signature, subject, requested_scopes, granted_scopes, active, revoked, form_data, session_data) VALUES (?, ?, 'app', ?, 's', '', '', TRUE, ?, '', '');`
	seedRefresh := `INSERT INTO oauth2_refresh_token_session (challenge_id, request_id, client_id, signature, subject, requested_scopes, granted_scopes, active, revoked, form_data, session_data) VALUES (?, ?, 'app', ?, 's', '', '', TRUE, ?, '', '');`

	for _, seed := range []struct {
		query     string
		challenge string
		requestID string
		signature string
		revoked   bool
	}{
		{seedAccess, "c", "a", "at_a1", true},
		{seedRefresh, "c", "a", "rt_a1", true},
		{seedAccess, "c", "a", "at_a2", false},
		{seedRefresh, "c", "a", "rt_a2", false},
		{seedAccess, "c", "b", "at_b1", false},
		{seedAccess, "c", "b", "at_b2", false},
		{seedRefresh, "c", "b", "rt_b1", false},
		{seedAccess, "c", "c", "at_c1", true},
		{seedRefresh, "c", "c", "rt_c1", false},
	} {
		_, err = provider.db.ExecContext(ctx, seed.query, seed.challenge, seed.requestID, seed.signature, seed.revoked)

		require.NoError(t, err)
	}

	require.NoError(t, provider.SchemaMigrate(ctx, true, 27))

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var actual string

			require.NoError(t, provider.db.GetContext(ctx, &actual, "SELECT access_signature FROM oauth2_refresh_token_session WHERE signature = ?;", tc.signature))

			assert.Equal(t, tc.expected, actual)
		})
	}
}

func TestSchemaMigrateRemovesDuplicateDeviceCodeSessions(t *testing.T) {
	testCases := []struct {
		name     string
		id       int
		expected bool
	}{
		{"ShouldRemoveOlderDuplicateSignature", 1, false},
		{"ShouldKeepNewerDuplicateSignature", 2, true},
		{"ShouldRemoveOlderDuplicateUserCodeSignature", 3, false},
		{"ShouldKeepNewerDuplicateUserCodeSignature", 4, true},
		{"ShouldKeepUnique", 5, true},
	}

	config := &schema.Configuration{
		Storage: schema.Storage{
			EncryptionKey: "authelia-test-key-not-a-secret-authelia-test-key-not-a-secret",
			Local:         &schema.StorageLocal{Path: filepath.Join(t.TempDir(), "db.sqlite3")},
		},
	}

	ctx := context.Background()

	provider, err := NewSQLiteProvider(config)

	require.NoError(t, err)

	t.Cleanup(func() {
		_ = provider.Close()
	})

	require.NoError(t, provider.SchemaMigrate(ctx, true, 31))

	seed := `INSERT INTO oauth2_device_code_session (id, request_id, client_id, signature, user_code_signature, status, requested_scopes, granted_scopes, form_data, session_data) VALUES (?, 'r', 'app', ?, ?, 0, '', '', '', '');`

	for _, row := range []struct {
		id        int
		signature string
		userCode  string
	}{
		{1, "dc_1", "uc_1"},
		{2, "dc_1", "uc_2"},
		{3, "dc_3", "uc_3"},
		{4, "dc_4", "uc_3"},
		{5, "dc_5", "uc_5"},
	} {
		_, err = provider.db.ExecContext(ctx, seed, row.id, row.signature, row.userCode)

		require.NoError(t, err)
	}

	require.NoError(t, provider.SchemaMigrate(ctx, true, 32))

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var count int

			require.NoError(t, provider.db.GetContext(ctx, &count, "SELECT COUNT(*) FROM oauth2_device_code_session WHERE id = ?;", tc.id))

			assert.Equal(t, tc.expected, count == 1)
		})
	}
}

func TestSchemaMigrateBackfillsOAuth2OneTimeConsumption(t *testing.T) {
	config := &schema.Configuration{
		Storage: schema.Storage{
			EncryptionKey: "authelia-test-key-not-a-secret-authelia-test-key-not-a-secret",
			Local:         &schema.StorageLocal{Path: filepath.Join(t.TempDir(), "db.sqlite3")},
		},
	}

	ctx := context.Background()

	provider, err := NewSQLiteProvider(config)
	require.NoError(t, err)

	t.Cleanup(func() {
		_ = provider.Close()
	})

	require.NoError(t, provider.SchemaMigrate(ctx, true, 34))

	seedAuthorizeCode := `INSERT INTO oauth2_authorization_code_session (challenge_id, request_id, client_id, signature, subject, requested_scopes, granted_scopes, active, revoked, form_data, session_data) VALUES ('challenge', 'request', 'client', ?, 'subject', '', '', ?, ?, '', '');`
	seedPAR := `INSERT INTO oauth2_par_context (signature, request_id, client_id, scopes, audience, handled_response_types, response_mode, response_mode_default, revoked, form_data, session_data) VALUES (?, 'request', 'client', '', '', '', '', '', ?, '', '');`

	for _, seed := range []struct {
		query string
		args  []any
	}{
		{seedAuthorizeCode, []any{"ac_consumed", false, false}},
		{seedAuthorizeCode, []any{"ac_revoked", true, true}},
		{seedAuthorizeCode, []any{"ac_active", true, false}},
		{seedPAR, []any{"par_consumed", true}},
		{seedPAR, []any{"par_active", false}},
	} {
		_, err = provider.db.ExecContext(ctx, seed.query, seed.args...)
		require.NoError(t, err)
	}

	require.NoError(t, provider.SchemaMigrate(ctx, true, 35))

	for _, tc := range []struct {
		name      string
		oneTime   model.OAuth2OneTimeType
		clientID  string
		signature string
		consumed  bool
	}{
		{"ShouldBackfillConsumedAuthorizeCode", model.OAuth2OneTimeTypeAuthorizeCode, "", "ac_consumed", true},
		{"ShouldBackfillRevokedAuthorizeCode", model.OAuth2OneTimeTypeAuthorizeCode, "", "ac_revoked", true},
		{"ShouldNotBackfillActiveAuthorizeCode", model.OAuth2OneTimeTypeAuthorizeCode, "", "ac_active", false},
		{"ShouldBackfillRevokedPAR", model.OAuth2OneTimeTypePushedAuthorizationRequest, "", "par_consumed", true},
		{"ShouldNotBackfillActivePAR", model.OAuth2OneTimeTypePushedAuthorizationRequest, "", "par_active", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			consumed, err := provider.IsOAuth2OneTimeConsumed(ctx, tc.oneTime, tc.clientID, tc.signature)
			require.NoError(t, err)
			assert.Equal(t, tc.consumed, consumed)
		})
	}
}
