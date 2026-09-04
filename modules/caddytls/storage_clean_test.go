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

package caddytls

import (
	"context"
	"io/fs"
	"sync"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/certmagic"
	"github.com/cloudflare/circl/hpke"
	"go.uber.org/zap"
)

var (
	testStorageMu     sync.Mutex
	activeTestStorage certmagic.Storage
)

type testStorageModule struct{}

func (testStorageModule) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "caddy.storage.test_blocking",
		New: func() caddy.Module { return new(testStorageModule) },
	}
}

func (testStorageModule) CertMagicStorage() (certmagic.Storage, error) {
	testStorageMu.Lock()
	defer testStorageMu.Unlock()
	return activeTestStorage, nil
}

func init() {
	caddy.RegisterModule(testStorageModule{})
}

func newTestContextWithStorage(t *testing.T, storage certmagic.Storage) (caddy.Context, context.CancelFunc) {
	testStorageMu.Lock()
	activeTestStorage = storage
	testStorageMu.Unlock()

	cfg := &caddy.Config{
		StorageRaw: []byte(`{"module": "test_blocking"}`),
	}
	ctx, err := caddy.ProvisionContext(cfg)
	if err != nil {
		t.Fatalf("caddy.ProvisionContext failed: %v", err)
	}
	return ctx, func() {
		testStorageMu.Lock()
		activeTestStorage = nil
		testStorageMu.Unlock()
	}
}

type blockingStorage struct {
	lockFunc   func(ctx context.Context, key string) error
	unlockFunc func(ctx context.Context, key string) error
	storeFunc  func(ctx context.Context, key string, value []byte) error
	loadFunc   func(ctx context.Context, key string) ([]byte, error)
	deleteFunc func(ctx context.Context, key string) error
	existsFunc func(ctx context.Context, key string) bool
	listFunc   func(ctx context.Context, path string, recursive bool) ([]string, error)
	statFunc   func(ctx context.Context, key string) (certmagic.KeyInfo, error)
}

func (s *blockingStorage) Lock(ctx context.Context, key string) error {
	if s.lockFunc != nil {
		return s.lockFunc(ctx, key)
	}
	return nil
}

func (s *blockingStorage) Unlock(ctx context.Context, key string) error {
	if s.unlockFunc != nil {
		return s.unlockFunc(ctx, key)
	}
	return nil
}

func (s *blockingStorage) Store(ctx context.Context, key string, value []byte) error {
	if s.storeFunc != nil {
		return s.storeFunc(ctx, key, value)
	}
	return nil
}

func (s *blockingStorage) Load(ctx context.Context, key string) ([]byte, error) {
	if s.loadFunc != nil {
		return s.loadFunc(ctx, key)
	}
	return nil, fs.ErrNotExist
}

func (s *blockingStorage) Delete(ctx context.Context, key string) error {
	if s.deleteFunc != nil {
		return s.deleteFunc(ctx, key)
	}
	return nil
}

func (s *blockingStorage) Exists(ctx context.Context, key string) bool {
	if s.existsFunc != nil {
		return s.existsFunc(ctx, key)
	}
	return false
}

func (s *blockingStorage) List(ctx context.Context, path string, recursive bool) ([]string, error) {
	if s.listFunc != nil {
		return s.listFunc(ctx, path, recursive)
	}
	return nil, nil
}

func (s *blockingStorage) Stat(ctx context.Context, key string) (certmagic.KeyInfo, error) {
	if s.statFunc != nil {
		return s.statFunc(ctx, key)
	}
	return certmagic.KeyInfo{}, fs.ErrNotExist
}

type blockingPublisher struct {
	publishFunc func(ctx context.Context, innerNames []string, echConfigList []byte) error
}

func (p *blockingPublisher) PublisherKey() string {
	return "blocking_test_publisher"
}

func (p *blockingPublisher) PublishECHConfigList(ctx context.Context, innerNames []string, echConfigList []byte) error {
	if p.publishFunc != nil {
		return p.publishFunc(ctx, innerNames, echConfigList)
	}
	return nil
}

func TestTLSStorageCleanStopSynchronization(t *testing.T) {
	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	defer cancel()

	tlsApp := &TLS{
		ctx:    ctx,
		logger: zap.NewNop(),
		Automation: &AutomationConfig{
			StorageCleanInterval: caddy.Duration(1 * time.Hour),
		},
	}

	// Start storage cleaner
	tlsApp.keepStorageClean()

	// Stop must cancel cleaner context and wait for completion cleanly
	err := tlsApp.Stop()
	if err != nil {
		t.Fatalf("TLS.Stop failed: %v", err)
	}
}

func TestTLSStorageCleanUnitsCanceledContext(t *testing.T) {
	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	cancel() // canceled immediately

	tlsApp := &TLS{
		ctx:    ctx,
		logger: zap.NewNop(),
	}

	// cleanStorageUnits with canceled context should return immediately
	tlsApp.cleanStorageUnits(ctx.Context)
}

func TestTLSECHStopSynchronization(t *testing.T) {
	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	defer cancel()

	tlsApp := &TLS{
		ctx:                  ctx,
		logger:               zap.NewNop(),
		Automation:           &AutomationConfig{},
		EncryptedClientHello: &ECH{},
		DisableStorageClean:  true,
	}

	err := tlsApp.Start()
	if err != nil {
		t.Fatalf("TLS.Start failed: %v", err)
	}

	// Stop must cancel ECH context and wait for background ECH worker to exit
	err = tlsApp.Stop()
	if err != nil {
		t.Fatalf("TLS.Stop failed: %v", err)
	}
}

func TestTLSStorageCleanBlockingStorageStopSynchronization(t *testing.T) {
	startedLock := make(chan struct{})
	storage := &blockingStorage{
		lockFunc: func(ctx context.Context, key string) error {
			if key == "storage_clean" {
				close(startedLock)
				<-ctx.Done()
				return ctx.Err()
			}
			return nil
		},
	}

	ctx, cleanup := newTestContextWithStorage(t, storage)
	defer cleanup()

	tlsApp := &TLS{
		ctx:    ctx,
		logger: zap.NewNop(),
		Automation: &AutomationConfig{
			StorageCleanInterval: caddy.Duration(1 * time.Hour),
		},
	}

	// Reset storageClean timestamp so cleaning runs
	storageCleanMu.Lock()
	storageClean = time.Time{}
	storageCleanMu.Unlock()

	tlsApp.keepStorageClean()

	select {
	case <-startedLock:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for storage lock to be attempted")
	}

	stopped := make(chan error, 1)
	go func() {
		stopped <- tlsApp.Stop()
	}()

	select {
	case err := <-stopped:
		if err != nil {
			t.Fatalf("TLS.Stop failed: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("TLS.Stop hung while storage cleaner was blocked on storage lock")
	}
}

func TestTLSECHPublishBlockingStorageStopSynchronization(t *testing.T) {
	startedLock := make(chan struct{})
	storage := &blockingStorage{
		lockFunc: func(ctx context.Context, key string) error {
			if key == "ech_publish" {
				close(startedLock)
				<-ctx.Done()
				return ctx.Err()
			}
			return nil
		},
	}

	ctx, cleanup := newTestContextWithStorage(t, storage)
	defer cleanup()

	ech := &ECH{
		configsMu: new(sync.RWMutex),
		Configs:   []ECHConfiguration{{PublicName: "example.com"}},
	}
	tlsApp := &TLS{
		ctx:                  ctx,
		logger:               zap.NewNop(),
		Automation:           &AutomationConfig{},
		EncryptedClientHello: ech,
		DisableStorageClean:  true,
	}

	err := tlsApp.Start()
	if err != nil {
		t.Fatalf("TLS.Start failed: %v", err)
	}

	select {
	case <-startedLock:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for ech_publish storage lock to be attempted")
	}

	stopped := make(chan error, 1)
	go func() {
		stopped <- tlsApp.Stop()
	}()

	select {
	case err := <-stopped:
		if err != nil {
			t.Fatalf("TLS.Stop failed: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("TLS.Stop hung while ECH publisher was blocked on ech_publish storage lock")
	}
}

func TestTLSECHPublishBlockingPublisherStopSynchronization(t *testing.T) {
	startedPublish := make(chan struct{})
	publisher := &blockingPublisher{
		publishFunc: func(ctx context.Context, innerNames []string, echConfigList []byte) error {
			close(startedPublish)
			<-ctx.Done()
			return ctx.Err()
		},
	}

	storage := &blockingStorage{}
	ctx, cleanup := newTestContextWithStorage(t, storage)
	defer cleanup()

	publicKey, _, err := hpke.KEM_X25519_HKDF_SHA256.Scheme().GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	ech := &ECH{
		configsMu: new(sync.RWMutex),
		Configs:   []ECHConfiguration{{PublicName: "example.com"}},
		Publication: []*ECHPublication{
			{
				Domains:    []string{"example.com"},
				publishers: []ECHPublisher{publisher},
			},
		},
		configs: map[string][]echConfig{
			"example.com": {
				{
					PublicKey:     publicKey,
					Version:       draftTLSESNI25,
					ConfigID:      1,
					RawPublicName: "example.com",
					KEMID:         hpke.KEM_X25519_HKDF_SHA256,
					CipherSuites: []hpkeSymmetricCipherSuite{
						{
							KDFID:  hpke.KDF_HKDF_SHA256,
							AEADID: hpke.AEAD_AES128GCM,
						},
					},
					meta: echConfigMeta{
						Publications: make(publicationHistory),
					},
				},
			},
		},
	}
	tlsApp := &TLS{
		ctx:                  ctx,
		logger:               zap.NewNop(),
		Automation:           &AutomationConfig{},
		EncryptedClientHello: ech,
		DisableStorageClean:  true,
		serverNames: map[string]serverNameRegistration{
			"example.com": {},
		},
	}

	err = tlsApp.Start()
	if err != nil {
		t.Fatalf("TLS.Start failed: %v", err)
	}

	select {
	case <-startedPublish:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for ECH publication to be attempted")
	}

	stopped := make(chan error, 1)
	go func() {
		stopped <- tlsApp.Stop()
	}()

	select {
	case err := <-stopped:
		if err != nil {
			t.Fatalf("TLS.Stop failed: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("TLS.Stop hung while ECH publisher was blocked inside PublishECHConfigList")
	}
}

func TestTLSECHRotateBlockingStorageStopSynchronization(t *testing.T) {
	startedLock := make(chan struct{})
	storage := &blockingStorage{
		lockFunc: func(ctx context.Context, key string) error {
			if key == echStorageLockName {
				close(startedLock)
				<-ctx.Done()
				return ctx.Err()
			}
			return nil
		},
	}

	ctx, cleanup := newTestContextWithStorage(t, storage)
	defer cleanup()

	ech := &ECH{
		configsMu: new(sync.RWMutex),
		Configs:   []ECHConfiguration{{PublicName: "example.com"}},
		configs: map[string][]echConfig{
			"example.com": {
				{
					ConfigID:      1,
					RawPublicName: "example.com",
					meta: echConfigMeta{
						Created:      time.Now().Add(-24 * time.Hour * 31), // > 30 days old so rotationNeeded returns true
						Publications: make(publicationHistory),
					},
				},
			},
		},
	}
	tlsApp := &TLS{
		ctx:                  ctx,
		logger:               zap.NewNop(),
		Automation:           &AutomationConfig{},
		EncryptedClientHello: ech,
		DisableStorageClean:  true,
		echRotateInterval:    5 * time.Millisecond,
	}

	err := tlsApp.Start()
	if err != nil {
		t.Fatalf("TLS.Start failed: %v", err)
	}

	select {
	case <-startedLock:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for echStorageLockName storage lock to be attempted during rotation")
	}

	stopped := make(chan error, 1)
	go func() {
		stopped <- tlsApp.Stop()
	}()

	select {
	case err := <-stopped:
		if err != nil {
			t.Fatalf("TLS.Stop failed: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("TLS.Stop hung while ECH key rotation was blocked on storage lock (context was likely ignored)")
	}
}
