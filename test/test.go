//go:build !integration
// +build !integration

package test

import (
	"testing"

	"github.com/zalando/go-keyring"
)

// Run runs a test with mocked keyring.
func Run( //nolint: thelper,nolintlint
	t *testing.T,
	service, key string,
	expect RunExpect,
	test func(t *testing.T),
) {
	keyring.MockInit()

	runTest(t, service, key, expect, test)
}
