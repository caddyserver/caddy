// Copyright 2015 Matthew Holt and The Caddy Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package caddypki

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/caddyserver/certmagic"
	"go.uber.org/zap"

	"github.com/caddyserver/caddy/v2"
)

// newSharedStorageCA returns a CA backed by storage, as each Caddy
// instance of a cluster sharing that storage would have.
func newSharedStorageCA(t *testing.T, storage certmagic.Storage) *CA {
	t.Helper()
	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	t.Cleanup(cancel)
	return &CA{
		ID:                     DefaultCAID,
		Name:                   defaultCAName,
		RootCommonName:         "Test Root",
		IntermediateCommonName: "Test Intermediate",
		IntermediateLifetime:   caddy.Duration(time.Hour),
		RenewalWindowRatio:     0.5,
		storage:                storage,
		ctx:                    ctx,
		mu:                     new(sync.RWMutex),
		log:                    zap.NewNop(),
	}
}

func TestRenewCertsForCA_SharedStorageConverges(t *testing.T) {
	storage := &certmagic.FileStorage{Path: t.TempDir()}

	// store a root and a short-lived intermediate, as an instance would at startup
	seed := newSharedStorageCA(t, storage)
	rootCert, rootKey, err := seed.loadOrGenRoot()
	if err != nil {
		t.Fatalf("generating root: %v", err)
	}
	seed.IntermediateLifetime = caddy.Duration(2 * time.Second)
	oldInter, _, err := seed.genIntermediate(rootCert, rootKey)
	if err != nil {
		t.Fatalf("generating intermediate: %v", err)
	}

	// several instances load that intermediate
	const instances = 4
	cas := make([]*CA, instances)
	for i := range cas {
		ca := newSharedStorageCA(t, storage)
		chain, key, err := ca.loadOrGenIntermediate(rootCert, rootKey)
		if err != nil {
			t.Fatalf("instance %d: loading intermediate: %v", i, err)
		}
		ca.root, ca.interChain, ca.interKey = rootCert, chain, key
		cas[i] = ca
	}

	// wait until it is in its renewal window, then let every instance renew at once
	time.Sleep(time.Until(oldInter.NotAfter.Add(-time.Second / 2)))
	if !cas[0].needsRenewal(cas[0].interChain[0]) {
		t.Fatal("intermediate should be in its renewal window")
	}
	pki := &PKI{log: zap.NewNop()}
	var wg sync.WaitGroup
	errs := make([]error, instances)
	for i, ca := range cas {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs[i] = pki.renewCertsForCA(ca)
		}()
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Fatalf("instance %d: renewing: %v", i, err)
		}
	}

	stored, storedKey, err := seed.loadIntermediate(rootCert)
	if err != nil {
		t.Fatalf("intermediate left in storage is unusable: %v", err)
	}
	if stored[0].Equal(oldInter) {
		t.Fatal("intermediate was not renewed")
	}
	if err := verifyKeysMatch(stored[0], storedKey); err != nil {
		t.Fatalf("stored intermediate does not match its key: %v", err)
	}
	for i, ca := range cas {
		if !ca.interChain[0].Equal(stored[0]) {
			t.Errorf("instance %d signs with intermediate %x, storage holds %x: instances did not converge",
				i, ca.interChain[0].SerialNumber, stored[0].SerialNumber)
		}
	}
}

func TestLoadOrGenIntermediate_ReplacesMismatchedPair(t *testing.T) {
	storage := &certmagic.FileStorage{Path: t.TempDir()}
	ca := newSharedStorageCA(t, storage)

	rootCert, rootKey, err := ca.loadOrGenRoot()
	if err != nil {
		t.Fatalf("generating root: %v", err)
	}
	first, _, err := ca.genIntermediate(rootCert, rootKey)
	if err != nil {
		t.Fatalf("generating intermediate: %v", err)
	}

	// leave the first intermediate's certificate next to another intermediate's key,
	// as two instances writing concurrently could
	_, otherKey, err := generateIntermediate("other", rootCert, rootKey, time.Hour)
	if err != nil {
		t.Fatalf("generating other intermediate: %v", err)
	}
	otherKeyPEM, err := certmagic.PEMEncodePrivateKey(otherKey)
	if err != nil {
		t.Fatalf("encoding key: %v", err)
	}
	if err := storage.Store(context.Background(), ca.storageKeyIntermediateKey(), otherKeyPEM); err != nil {
		t.Fatalf("storing key: %v", err)
	}
	if _, _, err := ca.loadIntermediate(rootCert); err == nil {
		t.Fatal("loading a mismatched intermediate should fail")
	}

	chain, key, err := ca.loadOrGenIntermediate(rootCert, rootKey)
	if err != nil {
		t.Fatalf("loading intermediate: %v", err)
	}
	if chain[0].Equal(first) {
		t.Fatal("mismatched intermediate was not replaced")
	}
	if err := verifyKeysMatch(chain[0], key); err != nil {
		t.Fatalf("new intermediate does not match its key: %v", err)
	}
	if _, _, err := ca.loadIntermediate(rootCert); err != nil {
		t.Fatalf("intermediate in storage is still unusable: %v", err)
	}
}

func TestLoadOrGenRoot_RejectsMismatchedPair(t *testing.T) {
	storage := &certmagic.FileStorage{Path: t.TempDir()}
	ca := newSharedStorageCA(t, storage)

	if _, _, err := ca.loadOrGenRoot(); err != nil {
		t.Fatalf("generating root: %v", err)
	}
	_, otherKey, err := generateRoot("other")
	if err != nil {
		t.Fatalf("generating other root: %v", err)
	}
	otherKeyPEM, err := certmagic.PEMEncodePrivateKey(otherKey)
	if err != nil {
		t.Fatalf("encoding key: %v", err)
	}
	if err := storage.Store(context.Background(), ca.storageKeyRootKey(), otherKeyPEM); err != nil {
		t.Fatalf("storing key: %v", err)
	}

	_, _, err = ca.loadOrGenRoot()
	if err == nil || !strings.Contains(err.Error(), "do not belong together") {
		t.Fatalf("expected a root mismatch error, got: %v", err)
	}
}
