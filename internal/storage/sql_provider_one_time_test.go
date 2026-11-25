// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package storage

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/authelia/authelia/v4/internal/model"
)

func TestSQLProviderConsumeOAuth2OneTime(t *testing.T) {
	provider := newTestSQLiteProviderWithEncryption(t)
	require.NoError(t, provider.StartupCheck())

	ctx := context.Background()
	expires := time.Now().Add(time.Hour).Truncate(time.Second)

	testCases := []struct {
		name     string
		oneTime  model.OAuth2OneTime
		expected string
	}{
		{
			name:     "ShouldConsumePKCEChallengeOnce",
			oneTime:  model.NewOAuth2OneTime(model.OAuth2OneTimeTypePKCEChallenge, "client-a", "challenge", expires),
			expected: "challenge",
		},
		{
			name:     "ShouldConsumeOpenIDConnectNonceOnce",
			oneTime:  model.NewOAuth2OneTime(model.OAuth2OneTimeTypeOpenIDConnectNonce, "client-a", "nonce", expires),
			expected: "nonce",
		},
		{
			name:     "ShouldConsumeAuthorizeCodeOnce",
			oneTime:  model.NewOAuth2OneTimeFromSignature(model.OAuth2OneTimeTypeAuthorizeCode, "", "authorize-code", expires),
			expected: "authorize-code",
		},
		{
			name:     "ShouldConsumePushedAuthorizationRequestOnce",
			oneTime:  model.NewOAuth2OneTimeFromSignature(model.OAuth2OneTimeTypePushedAuthorizationRequest, "", "request-uri", expires),
			expected: "request-uri",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			require.NoError(t, provider.ConsumeOAuth2OneTime(ctx, tc.oneTime))
			assert.ErrorIs(t, provider.ConsumeOAuth2OneTime(ctx, tc.oneTime), ErrNoRowsAffected)

			consumed, err := provider.IsOAuth2OneTimeConsumed(ctx, tc.oneTime.Type, tc.oneTime.ClientID, tc.oneTime.Signature)
			require.NoError(t, err)
			assert.True(t, consumed)
		})
	}

	t.Run("ShouldRefuseUndeclaredType", func(t *testing.T) {
		err := provider.ConsumeOAuth2OneTime(ctx, model.OAuth2OneTimeType("undeclared"), "client", "value", expires)

		assert.ErrorIs(t, err, ErrOAuth2OneTimeTypeNotDeclared)
	})

	t.Run("ShouldConsumeDeclaredTypeValues", func(t *testing.T) {
		require.NoError(t, provider.ConsumeOAuth2OneTime(ctx, model.OAuth2OneTimeTypePKCEChallenge, "client-b", "challenge-b", expires))
		assert.ErrorIs(t, provider.ConsumeOAuth2OneTime(ctx, model.OAuth2OneTimeTypePKCEChallenge, "client-b", "challenge-b", expires), ErrNoRowsAffected)
	})
}

func TestSQLProviderAuthorizeCodeConsumptionUsesOneTimeLedger(t *testing.T) {
	provider := newTestSQLiteProviderWithEncryption(t)
	require.NoError(t, provider.StartupCheck())

	ctx := context.Background()

	session := model.OAuth2Session{
		ChallengeID:     model.MustNullUUID(model.NewRandomNullUUID()),
		Signature:       "authorize-code-ledger",
		RequestID:       "request-id",
		ClientID:        "client",
		Subject:         sql.NullString{String: "subject", Valid: true},
		RequestedAt:     time.Now().Truncate(time.Second),
		RequestedScopes: model.StringSlicePipeDelimited{"openid"},
		GrantedScopes:   model.StringSlicePipeDelimited{"openid"},
		Active:          true,
		Session:         []byte("{}"),
	}

	require.NoError(t, provider.SaveOAuth2Session(ctx, OAuth2SessionTypeAuthorizeCode, session))
	require.NoError(t, provider.DeactivateOAuth2Session(ctx, OAuth2SessionTypeAuthorizeCode, session.Signature))

	consumed, err := provider.IsOAuth2OneTimeConsumed(ctx, model.OAuth2OneTimeTypeAuthorizeCode, "", session.Signature)
	require.NoError(t, err)
	assert.True(t, consumed)

	_, err = provider.db.ExecContext(ctx, "UPDATE oauth2_authorization_code_session SET active = TRUE WHERE signature = ?;", session.Signature)
	require.NoError(t, err)

	assert.ErrorIs(t, provider.DeactivateOAuth2Session(ctx, OAuth2SessionTypeAuthorizeCode, session.Signature), ErrNoRowsAffected)
}

func TestSQLProviderPushedAuthorizationConsumptionCanBeRearmed(t *testing.T) {
	provider := newTestSQLiteProviderWithEncryption(t)
	require.NoError(t, provider.StartupCheck())

	ctx := context.Background()

	par := model.OAuth2PushedAuthorizationSession{
		Signature:   "par-ledger",
		RequestID:   "par-request",
		ClientID:    "client",
		RequestedAt: time.Now().Truncate(time.Second),
		Session:     []byte("{}"),
	}

	require.NoError(t, provider.SaveOAuth2PushedAuthorizationSession(ctx, par))
	require.NoError(t, provider.RevokeOAuth2PushedAuthorizationSession(ctx, par.Signature))

	consumed, err := provider.IsOAuth2OneTimeConsumed(ctx, model.OAuth2OneTimeTypePushedAuthorizationRequest, "", par.Signature)
	require.NoError(t, err)
	assert.True(t, consumed)

	loaded, err := provider.LoadOAuth2PushedAuthorizationSession(ctx, par.Signature)
	require.NoError(t, err)
	assert.True(t, loaded.Revoked)

	loaded.Revoked = false
	require.NoError(t, provider.UpdateOAuth2PushedAuthorizationSession(ctx, *loaded))

	consumed, err = provider.IsOAuth2OneTimeConsumed(ctx, model.OAuth2OneTimeTypePushedAuthorizationRequest, "", par.Signature)
	require.NoError(t, err)
	assert.False(t, consumed)

	require.NoError(t, provider.RevokeOAuth2PushedAuthorizationSession(ctx, par.Signature))
}
