package token

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/bool64/ctxd"
	"github.com/nhatthm/moneyloverapi"
	"github.com/nhatthm/moneyloverapi/pkg/auth"
	"github.com/zalando/go-keyring"

	"github.com/nhatthm/moneyloverkeychain"
)

var (
	_ auth.TokenStorage = (*Storage)(nil)
	_ KeychainStorage   = (*Storage)(nil)
)

// KeychainStorage manages credentials in keychain.
type KeychainStorage interface {
	auth.TokenStorage

	// Delete deletes the token in keychain.
	Delete(ctx context.Context, key string) error
}

// StorageOption configures Storage.
type StorageOption func(s *Storage)

// Storage provides token from keychain.
type Storage struct {
	storage moneyloverkeychain.Storage
}

// Get gets token from keychain.
func (s *Storage) Get(ctx context.Context, key string) (auth.OAuthToken, error) {
	data, err := s.storage.Get(key)
	if err != nil {
		if errors.Is(err, keyring.ErrNotFound) {
			return auth.OAuthToken{}, nil
		}

		return auth.OAuthToken{}, err
	}

	var token auth.OAuthToken

	if err := json.Unmarshal([]byte(data), &token); err != nil {
		return auth.OAuthToken{}, ctxd.WrapError(ctx, err, "could not unmarshal token")
	}

	return token, nil
}

// Set persists token to keychain.
func (s *Storage) Set(ctx context.Context, key string, token auth.OAuthToken) error {
	data, err := json.Marshal(token)
	if err != nil {
		return ctxd.WrapError(ctx, err, "could not marshal token")
	}

	return s.storage.Set(key, string(data))
}

// Delete deletes the token in keychain.
func (s *Storage) Delete(_ context.Context, key string) error {
	err := s.storage.Delete(key)
	if err != nil && errors.Is(err, keyring.ErrNotFound) {
		return nil
	}

	return err
}

// NewStorage returns keychain as a token storage.
func NewStorage(options ...StorageOption) *Storage {
	s := &Storage{
		storage: moneyloverkeychain.NewStorage(tokenStorageService),
	}

	for _, o := range options {
		o(s)
	}

	return s
}

// WithKeyring sets keychain storage for Storage.
func WithKeyring(storage moneyloverkeychain.Storage) StorageOption {
	return func(s *Storage) {
		s.storage = storage
	}
}

// WithTokenStorage sets keychain as a token storage for moneylover client.
func WithTokenStorage(options ...StorageOption) moneyloverapi.Option {
	return moneyloverapi.WithTokenStorage(NewStorage(options...))
}
