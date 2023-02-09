//go:build !integration
// +build !integration

package credentials

import (
	"errors"
	"testing"

	"github.com/bool64/ctxd"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zalando/go-keyring"

	"github.com/nhatthm/moneyloverkeychain"
	"github.com/nhatthm/moneyloverkeychain/mock"
	"github.com/nhatthm/moneyloverkeychain/test"
)

func TestCredentials_Username(t *testing.T) {
	t.Parallel()

	deviceID := uuid.New()

	testCases := []struct {
		scenario       string
		mockStorage    mock.StorageMocker
		expectedResult string
		expectedError  string
	}{
		{
			scenario: "missing credentials",
			mockStorage: mock.MockStorage(func(s *mock.Storage) {
				s.On("Get", deviceID.String()).Return("", keyring.ErrNotFound)
			}),
		},
		{
			scenario: "could not get credentials",
			mockStorage: mock.MockStorage(func(s *mock.Storage) {
				s.On("Get", deviceID.String()).Return("", errors.New("get error"))
			}),
			expectedError: "error: could not get credentials {\"error\":{}}\n",
		},
		{
			scenario: "credentials is in wrong format",
			mockStorage: mock.MockStorage(func(s *mock.Storage) {
				s.On("Get", deviceID.String()).Return("{", nil)
			}),
			expectedError: "error: could not unmarshal credentials {\"error\":{\"Offset\":1}}\n",
		},
		{
			scenario: "success",
			mockStorage: mock.MockStorage(func(s *mock.Storage) {
				s.On("Get", deviceID.String()).Return(`{"username":"user@example.org","password":"123456"}`, nil)
			}),
			expectedResult: "user@example.org",
		},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.scenario, func(t *testing.T) {
			t.Parallel()

			s := tc.mockStorage(t)
			l := &ctxd.LoggerMock{}

			c := New(deviceID,
				WithStorage(s),
				WithLogger(l),
			)

			assert.Equal(t, tc.expectedResult, c.Username())
			assert.Equal(t, tc.expectedError, l.String())
		})
	}
}

func TestCredentials_Password(t *testing.T) {
	t.Parallel()

	deviceID := uuid.New()

	testCases := []struct {
		scenario       string
		mockStorage    mock.StorageMocker
		expectedResult string
		expectedError  string
	}{
		{
			scenario: "missing credentials",
			mockStorage: mock.MockStorage(func(s *mock.Storage) {
				s.On("Get", deviceID.String()).Return("", keyring.ErrNotFound)
			}),
		},
		{
			scenario: "could not get credentials",
			mockStorage: mock.MockStorage(func(s *mock.Storage) {
				s.On("Get", deviceID.String()).Return("", errors.New("get error"))
			}),
			expectedError: "error: could not get credentials {\"error\":{}}\n",
		},
		{
			scenario: "credentials is in wrong format",
			mockStorage: mock.MockStorage(func(s *mock.Storage) {
				s.On("Get", deviceID.String()).Return("{", nil)
			}),
			expectedError: "error: could not unmarshal credentials {\"error\":{\"Offset\":1}}\n",
		},
		{
			scenario: "success",
			mockStorage: mock.MockStorage(func(s *mock.Storage) {
				s.On("Get", deviceID.String()).Return(`{"username":"user@example.org","password":"123456"}`, nil)
			}),
			expectedResult: "123456",
		},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.scenario, func(t *testing.T) {
			t.Parallel()

			s := tc.mockStorage(t)
			l := &ctxd.LoggerMock{}

			c := New(deviceID,
				WithStorage(s),
				WithLogger(l),
			)

			assert.Equal(t, tc.expectedResult, c.Password())
			assert.Equal(t, tc.expectedError, l.String())
		})
	}
}

func TestCredentials_LoadOnce(t *testing.T) {
	deviceID := uuid.New()

	expectedUsername := "user@example.org"
	expectedPassword := "123456"

	storage := mock.MockStorage(func(s *mock.Storage) {
		s.On("Get", deviceID.String()).
			Return(`{"username":"user@example.org","password":"123456"}`, nil).
			Once()
	})(t)

	c := New(deviceID, WithStorage(storage))

	// 1st run calls storage.
	assert.Equal(t, expectedUsername, c.Username())
	assert.Equal(t, expectedPassword, c.Password())

	// 2nd run does not call storage.
	assert.Equal(t, expectedUsername, c.Username())
	assert.Equal(t, expectedPassword, c.Password())
}

func TestCredentials_LoadKeyring(t *testing.T) {
	deviceID := uuid.New()

	expect := func(t *testing.T, s moneyloverkeychain.Storage) { //nolint: thelper
		err := s.Set(deviceID.String(), `{"username":"user@example.org","password":"123456"}`)
		require.NoError(t, err)
	}

	expectedUsername := "user@example.org"
	expectedPassword := "123456"

	test.Run(t, credentialsService, deviceID.String(), expect, func(t *testing.T) { //nolint: thelper
		c := New(deviceID)

		assert.Equal(t, expectedUsername, c.Username())
		assert.Equal(t, expectedPassword, c.Password())
	})
}

func TestCredentials_Update(t *testing.T) {
	t.Parallel()

	deviceID := uuid.New()

	username := "user@example.org"
	password := "123456"

	testCases := []struct {
		scenario         string
		mockStorage      mock.StorageMocker
		expectedUsername string
		expectedPassword string
		expectedError    string
	}{
		{
			scenario: "could not update",
			mockStorage: mock.MockStorage(func(s *mock.Storage) {
				s.On("Set", deviceID.String(), `{"username":"user@example.org","password":"123456"}`).
					Return(errors.New("update error"))
			}),
			expectedError: "update error",
		},
		{
			scenario: "success",
			mockStorage: mock.MockStorage(func(s *mock.Storage) {
				s.On("Set", deviceID.String(), `{"username":"user@example.org","password":"123456"}`).
					Return(nil)
			}),
			expectedUsername: "user@example.org",
			expectedPassword: "123456",
		},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.scenario, func(t *testing.T) {
			t.Parallel()

			s := tc.mockStorage(t)
			c := New(deviceID, WithStorage(s))

			err := c.Update(username, password)

			if tc.expectedError == "" {
				assert.NoError(t, err)
				assert.Equal(t, tc.expectedUsername, c.Username())
				assert.Equal(t, tc.expectedPassword, c.Password())
			} else {
				assert.EqualError(t, err, tc.expectedError)
			}
		})
	}
}

func TestCredentials_UpdateOnce(t *testing.T) {
	deviceID := uuid.New()

	storage := mock.MockStorage(func(s *mock.Storage) {
		s.On("Get", deviceID.String()).
			Return(`{"username":"user@example.org","password":"123456"}`, nil).
			Once()

		s.On("Set", deviceID.String(), `{"username":"john@example.org","password":"654321"}`).
			Return(nil)
	})(t)

	c := New(deviceID, WithStorage(storage))

	// 1st run calls storage.
	expectedUsername := "user@example.org"
	expectedPassword := "123456"

	assert.Equal(t, expectedUsername, c.Username())
	assert.Equal(t, expectedPassword, c.Password())

	// Update.
	err := c.Update("john@example.org", "654321")
	require.NoError(t, err)

	// 2nd run does not call storage.
	expectedUsername = "john@example.org"
	expectedPassword = "654321"

	assert.Equal(t, expectedUsername, c.Username())
	assert.Equal(t, expectedPassword, c.Password())
}

func TestCredentials_UpdateKeyring(t *testing.T) {
	deviceID := uuid.New()

	expectedUsername := "user@example.org"
	expectedPassword := "123456"

	test.Run(t, credentialsService, deviceID.String(), nil, func(t *testing.T) { //nolint: thelper
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

func TestCredentials_Delete(t *testing.T) {
	t.Parallel()

	deviceID := uuid.New()

	testCases := []struct {
		scenario      string
		mockStorage   mock.StorageMocker
		expectedError string
	}{
		{
			scenario: "error not found",
			mockStorage: mock.MockStorage(func(s *mock.Storage) {
				s.On("Delete", deviceID.String()).Return(keyring.ErrNotFound)
			}),
		},
		{
			scenario: "could not delete",
			mockStorage: mock.MockStorage(func(s *mock.Storage) {
				s.On("Delete", deviceID.String()).Return(errors.New("delete error"))
			}),
			expectedError: "delete error",
		},
		{
			scenario: "success",
			mockStorage: mock.MockStorage(func(s *mock.Storage) {
				s.On("Delete", deviceID.String()).Return(nil)
			}),
		},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.scenario, func(t *testing.T) {
			t.Parallel()

			s := tc.mockStorage(t)
			c := New(deviceID, WithStorage(s))

			err := c.Delete()

			if tc.expectedError == "" {
				assert.NoError(t, err)
			} else {
				assert.EqualError(t, err, tc.expectedError)
			}
		})
	}
}

func TestCredentials_DeleteOnce(t *testing.T) {
	deviceID := uuid.New()

	storage := mock.MockStorage(func(s *mock.Storage) {
		s.On("Get", deviceID.String()).
			Return(`{"username":"user@example.org","password":"123456"}`, nil).
			Once()

		s.On("Delete", deviceID.String()).Return(nil).Once()

		s.On("Get", deviceID.String()).
			Return("", keyring.ErrNotFound).
			Once()
	})(t)

	c := New(deviceID, WithStorage(storage))

	// 1st run calls storage.
	expectedUsername := "user@example.org"
	expectedPassword := "123456"

	assert.Equal(t, expectedUsername, c.Username())
	assert.Equal(t, expectedPassword, c.Password())

	// Delete.
	err := c.Delete()
	require.NoError(t, err)

	// 2nd run calls storage again.
	assert.Empty(t, c.Username())
	assert.Empty(t, c.Password())
}

func TestCredentials_DeleteKeyring(t *testing.T) {
	deviceID := uuid.New()

	expect := func(t *testing.T, s moneyloverkeychain.Storage) { //nolint: thelper
		err := s.Set(deviceID.String(), `{"username":"user@example.org","password":"123456"}`)
		require.NoError(t, err)
	}

	expectedUsername := "user@example.org"
	expectedPassword := "123456"

	test.Run(t, credentialsService, deviceID.String(), expect, func(t *testing.T) { //nolint: thelper
		c := New(deviceID)

		assert.Equal(t, expectedUsername, c.Username())
		assert.Equal(t, expectedPassword, c.Password())

		// Delete.
		err := c.Delete()
		require.NoError(t, err)

		// The key should not be found anymore.
		_, err = keyring.Get(credentialsService, deviceID.String())
		assert.Equal(t, keyring.ErrNotFound, err)
	})
}
