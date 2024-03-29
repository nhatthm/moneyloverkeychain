//go:build integration
// +build integration

package token

import (
	"context"
	"testing"
	"time"

	"github.com/nhatthm/moneyloverapi/pkg/auth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zalando/go-keyring"

	"github.com/nhatthm/moneyloverkeychain"
	"github.com/nhatthm/moneyloverkeychain/test"
)

var tokenStorageKey = "user@example.org"

func TestIntegrationTokenStorage_GetKeyringNotFound(t *testing.T) {
	expectedToken := auth.OAuthToken{}

	test.Run(t, tokenStorageService, tokenStorageKey, nil, func(t *testing.T) { //nolint: thelper
		p := NewStorage()

		_, err := keyring.Get(tokenStorageService, tokenStorageKey)
		assert.Equal(t, keyring.ErrNotFound, err)

		token, err := p.Get(context.Background(), tokenStorageKey)

		assert.Equal(t, expectedToken, token)
		require.NoError(t, err)
	})
}

func TestIntegrationTokenStorage_GetKeyring(t *testing.T) {
	expect := func(t *testing.T, s moneyloverkeychain.Storage) { //nolint: thelper
		err := s.Set(tokenStorageKey, `{"access_token":"access","expires_at":"2020-01-02T03:04:05.000Z"}`)
		require.NoError(t, err)
	}

	expectedToken := auth.OAuthToken{
		AccessToken: "access",
		ExpiresAt:   time.Date(2020, 1, 2, 3, 4, 5, 0, time.UTC),
	}

	test.Run(t, tokenStorageService, tokenStorageKey, expect, func(t *testing.T) { //nolint: thelper
		p := NewStorage()

		token, err := p.Get(context.Background(), tokenStorageKey)

		assert.Equal(t, expectedToken, token)
		require.NoError(t, err)
	})
}

func TestIntegrationTokenStorage_SetKeyring(t *testing.T) {
	expectedToken := auth.OAuthToken{
		AccessToken: "access",
		ExpiresAt:   time.Date(2020, 1, 2, 3, 4, 5, 0, time.UTC),
	}

	test.Run(t, tokenStorageService, tokenStorageKey, nil, func(t *testing.T) { //nolint: thelper
		p := NewStorage()

		err := p.Set(context.Background(), tokenStorageKey, expectedToken)
		require.NoError(t, err)

		// Get from keychain.
		data, err := keyring.Get(tokenStorageService, tokenStorageKey)
		expectedData := `{"access_token":"access","expires_at":"2020-01-02T03:04:05Z"}`

		assert.Equal(t, expectedData, data)
		require.NoError(t, err)
	})
}

func TestIntegrationTokenStorage_DeleteKeyring(t *testing.T) {
	token := auth.OAuthToken{
		AccessToken: "access",
		ExpiresAt:   time.Date(2020, 1, 2, 3, 4, 5, 0, time.UTC),
	}

	test.Run(t, tokenStorageService, tokenStorageKey, nil, func(t *testing.T) { //nolint: thelper
		p := NewStorage()

		// Prepare data.
		err := p.Set(context.Background(), tokenStorageKey, token)
		require.NoError(t, err)

		// Verify data.
		_, err = keyring.Get(tokenStorageService, tokenStorageKey)
		require.NoError(t, err)

		// Test.
		err = p.Delete(context.Background(), tokenStorageKey)
		require.NoError(t, err)

		// Verify.
		_, err = keyring.Get(tokenStorageService, tokenStorageKey)
		assert.Equal(t, keyring.ErrNotFound, err)
	})
}

func TestIntegrationTokenStorage_DeleteKeyringNotFound(t *testing.T) {
	test.Run(t, tokenStorageService, tokenStorageKey, nil, func(t *testing.T) { //nolint: thelper
		p := NewStorage()

		_, err := keyring.Get(tokenStorageService, tokenStorageKey)
		assert.Equal(t, keyring.ErrNotFound, err)

		// Test.
		err = p.Delete(context.Background(), tokenStorageKey)
		require.NoError(t, err)
	})
}
