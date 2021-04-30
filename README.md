# Keychain Storage for MoneyLover API Client

[![GitHub Releases](https://img.shields.io/github/v/release/nhatthm/moneyloverkeychain)](https://github.com/nhatthm/moneyloverkeychain/releases/latest)
[![Build Status](https://github.com/nhatthm/moneyloverkeychain/actions/workflows/test.yaml/badge.svg)](https://github.com/nhatthm/moneyloverkeychain/actions/workflows/test.yaml)
[![codecov](https://codecov.io/gh/nhatthm/moneyloverkeychain/branch/master/graph/badge.svg?token=eTdAgDE2vR)](https://codecov.io/gh/nhatthm/moneyloverkeychain)
[![Go Report Card](https://goreportcard.com/badge/github.com/nhatthm/httpmock)](https://goreportcard.com/report/github.com/nhatthm/httpmock)
[![GoDevDoc](https://img.shields.io/badge/dev-doc-00ADD8?logo=go)](https://pkg.go.dev/github.com/nhatthm/moneyloverkeychain)
[![Donate](https://img.shields.io/badge/Donate-PayPal-green.svg)](https://www.paypal.com/donate/?hosted_button_id=PJZSGJN57TDJY)

`moneyloverkeychain` uses [system keyring](https://github.com/zalando/go-keyring#go-keyring-library) as a storage for
persisting/getting credentials and token. It supports OS X, Linux
(dbus) and Windows.

## Prerequisites

- `Go >= 1.15`

## Install

```bash
go get github.com/nhatthm/moneyloverkeychain
```

## Usage

### `moneyloverapi.CredentialsProvider`

**Examples**

Build `moneyloverapi.Client`:

```go
package mypackage

import (
	"github.com/nhatthm/moneyloverapi"
	"github.com/nhatthm/moneyloverkeychain/credentials"
)

func buildClient(username string) (*moneyloverapi.Client, error) {
	c := moneyloverapi.NewClient(
		credentials.WithCredentialsProvider(username),
	)

	return c, nil
}
```

Persist credentials in system keyring:

```go
package mypackage

import (
	"github.com/nhatthm/moneyloverkeychain/credentials"
)

func persist(username, password string) error {
	c := credentials.New(username)

	return c.Update(password)
}
```

### `auth.TokenStorage`

```go
package mypackage

import (
	"github.com/nhatthm/moneyloverapi"
	"github.com/nhatthm/moneyloverkeychain/token"
)

func buildClient() *moneyloverapi.Client {
	return moneyloverapi.NewClient(
		token.WithTokenStorage(),
	)
}
```

## Donation

If this project help you reduce time to develop, you can give me a cup of coffee :)

### Paypal donation

[![paypal](https://www.paypalobjects.com/en_US/i/btn/btn_donateCC_LG.gif)](https://www.paypal.com/donate/?hosted_button_id=PJZSGJN57TDJY)

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;or scan this

<img src="https://user-images.githubusercontent.com/1154587/113494222-ad8cb200-94e6-11eb-9ef3-eb883ada222a.png" width="147px" />
