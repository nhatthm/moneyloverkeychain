// +build integration

package credentials

import (
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	keyring "github.com/zalando/go-keyring"

	"github.com/nhatthm/moneyloverkeychain"
	"github.com/nhatthm/moneyloverkeychain/test"
)

func TestIntegrationCredentials_LoadKeyringNotFound(t *testing.T) {
	deviceID := uuid.New()

	test.Run(t, credentialsService, deviceID.String(), nil, func(t *testing.T) { // nolint: thelper
		c := New(deviceID)

		assert.Empty(t, c.Username())
		assert.Empty(t, c.Password())
	})
}

func TestIntegrationCredentials_LoadKeyring(t *testing.T) {
	deviceID := uuid.New()

	expect := func(t *testing.T, s moneyloverkeychain.Storage) { // nolint: thelper
		err := s.Set(deviceID.String(), `{"username":"user@example.org","password":"123456"}`)
		require.NoError(t, err)
	}

	expectedUsername := "user@example.org"
	expectedPassword := "123456"

	test.Run(t, credentialsService, deviceID.String(), expect, func(t *testing.T) { // nolint: thelper
		c := New(deviceID)

		assert.Equal(t, expectedUsername, c.Username())
		assert.Equal(t, expectedPassword, c.Password())
	})
}

func TestIntegrationCredentials_UpdateKeyring(t *testing.T) {
	deviceID := uuid.New()

	expectedUsername := "user@example.org"
	expectedPassword := "123456"

	test.Run(t, credentialsService, deviceID.String(), nil, func(t *testing.T) { // nolint: thelper
		c := New(deviceID)

		_, err := keyring.Get(credentialsService, deviceID.String())
		require.Equal(t, keyring.ErrNotFound, err)

		err = c.Update("user@example.org", "123456")
		assert.NoError(t, err)

		assert.Equal(t, expectedUsername, c.Username())
		assert.Equal(t, expectedPassword, c.Password())

		// Get from keychain.
		data, err := keyring.Get(credentialsService, deviceID.String())
		expectedData := `{"username":"user@example.org","password":"123456"}`

		assert.Equal(t, expectedData, data)
		assert.NoError(t, err)
	})
}

func TestIntegrationCredentials_DeleteKeyring(t *testing.T) {
	deviceID := uuid.New()

	expect := func(t *testing.T, s moneyloverkeychain.Storage) { // nolint: thelper
		err := s.Set(deviceID.String(), `{"username":"user@example.org","password":"123456"}`)
		require.NoError(t, err)
	}

	expectedUsername := "user@example.org"
	expectedPassword := "123456"

	test.Run(t, credentialsService, deviceID.String(), expect, func(t *testing.T) { // nolint: thelper
		c := New(deviceID)

		_, err := keyring.Get(credentialsService, deviceID.String())
		require.NoError(t, err)

		assert.Equal(t, expectedUsername, c.Username())
		assert.Equal(t, expectedPassword, c.Password())

		// Delete.
		err = c.Delete()
		require.NoError(t, err)

		// The key should not be found anymore.
		_, err = keyring.Get(credentialsService, deviceID.String())
		assert.Equal(t, keyring.ErrNotFound, err)
	})
}

func TestIntegrationCredentials_DeleteKeyringNotFound(t *testing.T) {
	deviceID := uuid.New()

	test.Run(t, credentialsService, deviceID.String(), nil, func(t *testing.T) { // nolint: thelper
		c := New(deviceID)

		_, err := keyring.Get(credentialsService, deviceID.String())
		require.Equal(t, keyring.ErrNotFound, err)

		// Delete.
		err = c.Delete()
		require.NoError(t, err)
	})
}
