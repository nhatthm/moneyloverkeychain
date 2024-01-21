package moneyloverkeychain_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zalando/go-keyring"

	"github.com/nhatthm/moneyloverkeychain"
	"github.com/nhatthm/moneyloverkeychain/test"
)

func TestStorage(t *testing.T) {
	service := "storage"
	key := "test"

	s := moneyloverkeychain.NewStorage(service)

	test.Run(t, service, key, nil, func(t *testing.T) { //nolint: thelper
		// Get not found.
		data, err := s.Get(key)

		assert.Empty(t, data)
		assert.Equal(t, keyring.ErrNotFound, err)

		// Set.
		err = s.Set(key, "foobar")
		require.NoError(t, err)

		data, err = s.Get(key)

		assert.Equal(t, "foobar", data)
		require.NoError(t, err)

		// Delete.
		err = s.Delete(key)
		require.NoError(t, err)

		data, err = s.Get(key)

		assert.Empty(t, data)
		assert.Equal(t, keyring.ErrNotFound, err)
	})
}
