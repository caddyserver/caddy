// Copyright 2015 Google Inc. All rights reserved.
// Use of this source code is governed by the Apache 2.0
// license that can be found in the LICENSE file.

// +build appengine

package user

import (
	"appengine/user"

	"golang.org/x/net/context"

	"google.golang.org/appengine/internal"
)

func Current(ctx context.Context) *User {
	c, err := internal.ClassicContextFromContext(ctx)
	if err != nil {
		panic(err)
	}
	u := user.Current(c)
	if u == nil {
		return nil
	}
	// Map appengine/user.User to this package's User type.
	return &User{
		Email:             u.Email,
		AuthDomain:        u.AuthDomain,
		Admin:             u.Admin,
		ID:                u.ID,
		FederatedIdentity: u.FederatedIdentity,
		FederatedProvider: u.FederatedProvider,
	}
}

func IsAdmin(ctx context.Context) bool {
	c, err := internal.ClassicContextFromContext(ctx)
	if err != nil {
		panic(err)
	}

	return user.IsAdmin(c)
}
