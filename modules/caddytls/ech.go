package caddytls

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	weakrand "math/rand/v2"
	"path"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/caddyserver/certmagic"
	"github.com/cloudflare/circl/hpke"
	"github.com/cloudflare/circl/kem"
	"github.com/libdns/libdns"
	"go.uber.org/zap"
	"golang.org/x/crypto/cryptobyte"

	"github.com/caddyserver/caddy/v2"
)

func init() {
	caddy.RegisterModule(ECHDNSPublisher{})
}

// ECH enables Encrypted ClientHello (ECH) and configures its management.
//
// ECH helps protect site names (also called "server names" or "domain names"
// or "SNI"), which are normally sent over plaintext when establishing a TLS
// connection. With ECH, the true ClientHello is encrypted and wrapped by an
// "outer" ClientHello that uses a more generic, shared server name that is
// publicly known.
//
// Clients need to know which public name (and other parameters) to use when
// connecting to a site with ECH, and the methods for this vary; however,
// major browsers support reading ECH configurations from DNS records (which
// is typically only secure when DNS-over-HTTPS or DNS-over-TLS is enabled in
// the client). Caddy has the ability to automatically publish ECH configs to
// DNS records if a DNS provider is configured either in the TLS app or with
// each individual publication config object. (Requires a custom build with a
// DNS provider module.)
//
// ECH requires at least TLS 1.3, so any TLS connection policies with ECH
// applied will automatically upgrade the minimum TLS version to 1.3, even if
// configured to a lower version.
//
// Note that, as of Caddy 2.10.0 (~March 2025), ECH keys are not automatically
// rotated due to a limitation in the Go standard library (see
// https://github.com/golang/go/issues/71920). This should be resolved when
// Go 1.25 is released (~Aug. 2025), and Caddy will be updated to automatically
// rotate ECH keys/configs at that point.
//
// EXPERIMENTAL: Subject to change.
type ECH struct {
	// The list of ECH configurations for which to automatically generate
	// and rotate keys. At least one is required to enable ECH.
	//
	// It is strongly recommended to use as few ECH configs as possible
	// to maximize the size of your anonymity set (see the ECH specification
	// for a definition). Typically, each server should have only one public
	// name, i.e. one config in this list.
	Configs []ECHConfiguration `json:"configs,omitempty"`

	// Publication describes ways to publish ECH configs for clients to
	// discover and use. Without publication, most clients will not use
	// ECH at all, and those that do will suffer degraded performance.
	//
	// Most major browsers support ECH by way of publication to HTTPS
	// DNS RRs. (This also typically requires that they use DoH or DoT.)
	Publication []*ECHPublication `json:"publication,omitempty"`

	configsMu   *sync.RWMutex                 // protects both configs and the list of configs/keys the standard library uses
	configs     map[string][]echConfig        // map of public_name to list of configs
	stdlibReady []tls.EncryptedClientHelloKey // ECH configs+keys in a format the standard library can use
}

// Provision loads or creates ECH configs and returns outer names (for certificate
// management), but does not publish any ECH configs. The DNS module is used as
// a default for later publishing if needed.
func (ech *ECH) Provision(ctx caddy.Context) ([]string, error) {
	ech.configsMu = new(sync.RWMutex)

	logger := ctx.Logger().Named("ech")

	// set up publication modules before we need to obtain a lock in storage,
	// since this is strictly internal and doesn't require synchronization
	for i, pub := range ech.Publication {
		mods, err := ctx.LoadModule(pub, "PublishersRaw")
		if err != nil {
			return nil, fmt.Errorf("loading ECH publication modules: %v", err)
		}
		for _, modIface := range mods.(map[string]any) {
			ech.Publication[i].publishers = append(ech.Publication[i].publishers, modIface.(ECHPublisher))
		}
	}

	// the rest of provisioning needs an exclusive lock so that instances aren't
	// stepping on each other when setting up ECH configs
	storage := ctx.Storage()
	if err := storage.Lock(ctx, echStorageLockName); err != nil {
		return nil, err
	}
	defer func() {
		if err := storage.Unlock(ctx, echStorageLockName); err != nil {
			logger.Error("unable to unlock ECH provisioning in storage", zap.Error(err))
		}
	}()

	ech.configsMu.Lock()
	defer ech.configsMu.Unlock()

	outerNames, err := ech.setConfigsFromStorage(ctx, logger)
	if err != nil {
		return nil, fmt.Errorf("loading configs from storage: %w", err)
	}

	// see if we need to make any new ones based on the input configuration
	for _, cfg := range ech.Configs {
		publicName := strings.ToLower(strings.TrimSpace(cfg.PublicName))

		if list, ok := ech.configs[publicName]; !ok || len(list) == 0 {
			// no config with this public name was loaded, so create one
			echCfg, err := generateAndStoreECHConfig(ctx, publicName)
			if err != nil {
				return nil, err
			}
			logger.Debug("generated new ECH config",
				zap.String("public_name", echCfg.RawPublicName),
				zap.Uint8("id", echCfg.ConfigID))
			ech.configs[publicName] = append(ech.configs[publicName], echCfg)
			outerNames = append(outerNames, publicName)
		}
	}

	// ensure old keys are rotated out
	if err = ech.rotateECHKeys(ctx, logger, true); err != nil {
		return nil, fmt.Errorf("rotating ECH configs: %w", err)
	}

	return outerNames, nil
}

// setConfigsFromStorage sets the ECH configs in memory to those in storage.
// It must be called in a write lock on ech.configsMu.
func (ech *ECH) setConfigsFromStorage(ctx caddy.Context, logger *zap.Logger) ([]string, error) {
	storage := ctx.Storage()

	ech.configs = make(map[string][]echConfig)

	var outerNames []string

	// start by loading all the existing configs (even the older ones on the way out,
	// since some clients may still be using them if they haven't yet picked up on the
	// new configs)
	cfgKeys, err := storage.List(ctx, echConfigsKey, false)
	if err != nil && !errors.Is(err, fs.ErrNotExist) { // OK if dir doesn't exist; it will be created
		return nil, err
	}
	for _, cfgKey := range cfgKeys {
		cfg, err := loadECHConfig(ctx, path.Base(cfgKey))
		if err != nil {
			return nil, err
		}
		// if any part of the config's folder was corrupted, the load function will
		// clean it up and not return an error, since configs are immutable and
		// fairly ephemeral... so just check that we actually got a populated config
		if cfg.configBin == nil || cfg.privKeyBin == nil {
			continue
		}
		logger.Debug("loaded ECH config",
			zap.String("public_name", cfg.RawPublicName),
			zap.Uint8("id", cfg.ConfigID))
		if _, seen := ech.configs[cfg.RawPublicName]; !seen {
			outerNames = append(outerNames, cfg.RawPublicName)
		}
		ech.configs[cfg.RawPublicName] = append(ech.configs[cfg.RawPublicName], cfg)
	}

	return outerNames, nil
}

// rotateECHKeys updates the ECH keys/configs that are outdated. It should be called
// in a write lock on ech.configsMu. If a lock is already obtained in storage, then
// pass true for storageSynced.
func (ech *ECH) rotateECHKeys(ctx caddy.Context, logger *zap.Logger, storageSynced bool) error {
	storage := ctx.Storage()

	// all existing configs are now loaded; rotate keys "regularly" as recommended by the spec
	// (also: "Rotating too frequently limits the client anonymity set." - but the more server
	// names, the more frequently rotation can be done safely)
	const (
		rotationInterval = 24 * time.Hour * 30
		deleteAfter      = 24 * time.Hour * 90
	)

	if !ech.rotationNeeded(rotationInterval, deleteAfter) {
		return nil
	}

	// sync this operation across cluster if not already
	if !storageSynced {
		if err := storage.Lock(ctx, echStorageLockName); err != nil {
			return err
		}
		defer func() {
			if err := storage.Unlock(ctx, echStorageLockName); err != nil {
				logger.Error("unable to unlock ECH rotation in storage", zap.Error(err))
			}
		}()
	}

	// update what storage has, in case another instance already updated things
	if _, err := ech.setConfigsFromStorage(ctx, logger); err != nil {
		return fmt.Errorf("updating ECH keys from storage: %v", err)
	}

	// iterate the updated list and do any updates as needed
	for publicName := range ech.configs {
		for i := 0; i < len(ech.configs[publicName]); i++ {
			cfg := ech.configs[publicName][i]
			if time.Since(cfg.meta.Created) >= rotationInterval && cfg.meta.Replaced.IsZero() {
				// key is due for rotation and it hasn't been replaced yet; do that now
				logger.Debug("ECH config is due for rotation",
					zap.String("public_name", cfg.RawPublicName),
					zap.Uint8("id", cfg.ConfigID),
					zap.Time("created", cfg.meta.Created),
					zap.Duration("age", time.Since(cfg.meta.Created)),
					zap.Duration("rotation_interval", rotationInterval))

				// start by generating and storing the replacement ECH config
				newCfg, err := generateAndStoreECHConfig(ctx, publicName)
				if err != nil {
					return fmt.Errorf("generating and storing new replacement ECH config: %w", err)
				}

				// mark the key as replaced so we don't rotate it again, and instead delete it later
				ech.configs[publicName][i].meta.Replaced = time.Now()

				// persist the updated metadata
				metaBytes, err := json.Marshal(ech.configs[publicName][i].meta)
				if err != nil {
					return fmt.Errorf("marshaling updated ECH config metadata: %v", err)
				}
				if err := storage.Store(ctx, echMetaKey(cfg.ConfigID), metaBytes); err != nil {
					return fmt.Errorf("storing updated ECH config metadata: %v", err)
				}

				ech.configs[publicName] = append(ech.configs[publicName], newCfg)

				logger.Debug("rotated ECH key",
					zap.String("public_name", cfg.RawPublicName),
					zap.Uint8("old_id", cfg.ConfigID),
					zap.Uint8("new_id", newCfg.ConfigID))
			} else if time.Since(cfg.meta.Created) >= deleteAfter && !cfg.meta.Replaced.IsZero() {
				// key has expired and is no longer supported; delete it from storage and memory
				cfgIDKey := path.Join(echConfigsKey, strconv.Itoa(int(cfg.ConfigID)))
				if err := storage.Delete(ctx, cfgIDKey); err != nil {
					return fmt.Errorf("deleting expired ECH config: %v", err)
				}

				ech.configs[publicName] = append(ech.configs[publicName][:i], ech.configs[publicName][i+1:]...)
				i--

				logger.Debug("deleted expired ECH key",
					zap.String("public_name", cfg.RawPublicName),
					zap.Uint8("id", cfg.ConfigID),
					zap.Duration("age", time.Since(cfg.meta.Created)))
			}
		}
	}

	ech.updateKeyList()

	return nil
}

// rotationNeeded returns true if any ECH key needs to be replaced, or deleted.
// It must be called inside a read or write lock of ech.configsMu (probably a
// write lock, so that the rotation can occur correctly in the same lock).)
func (ech *ECH) rotationNeeded(rotationInterval, deleteAfter time.Duration) bool {
	for publicName := range ech.configs {
		for i := 0; i < len(ech.configs[publicName]); i++ {
			cfg := ech.configs[publicName][i]
			if (time.Since(cfg.meta.Created) >= rotationInterval && cfg.meta.Replaced.IsZero()) ||
				(time.Since(cfg.meta.Created) >= deleteAfter && !cfg.meta.Replaced.IsZero()) {
				return true
			}
		}
	}
	return false
}

// updateKeyList updates the list of ECH keys the std lib uses to serve ECH.
// It must be called inside a write lock on ech.configsMu.
func (ech *ECH) updateKeyList() {
	ech.stdlibReady = []tls.EncryptedClientHelloKey{}
	for _, cfgs := range ech.configs {
		for _, cfg := range cfgs {
			ech.stdlibReady = append(ech.stdlibReady, tls.EncryptedClientHelloKey{
				Config:      cfg.configBin,
				PrivateKey:  cfg.privKeyBin,
				SendAsRetry: cfg.meta.Replaced.IsZero(), // only send during retries if key has not been rotated out
			})
		}
	}
}

// publishECHConfigs publishes any configs that are configured for publication and which haven't been published already.
func (t *TLS) publishECHConfigs(logger *zap.Logger) error {
	// make publication exclusive, since we don't need to repeat this unnecessarily
	storage := t.ctx.Storage()
	const echLockName = "ech_publish"
	if err := storage.Lock(t.ctx, echLockName); err != nil {
		return err
	}
	defer func() {
		if err := storage.Unlock(t.ctx, echLockName); err != nil {
			logger.Error("unable to unlock ECH provisioning in storage", zap.Error(err))
		}
	}()

	// get the publication config, or use a default if not specified
	// (the default publication config should be to publish all ECH
	// configs to the app-global DNS provider; if no DNS provider is
	// configured, then this whole function is basically a no-op)
	publicationList := t.EncryptedClientHello.Publication
	if publicationList == nil {
		if dnsProv, ok := t.dns.(ECHDNSProvider); ok {
			publicationList = []*ECHPublication{
				{
					publishers: []ECHPublisher{
						&ECHDNSPublisher{
							provider: dnsProv,
							logger:   logger,
						},
					},
				},
			}
		}
	}

	// for each publication config, build the list of ECH configs to
	// publish with it, and figure out which inner names to publish
	// to/for, then publish
	for _, publication := range publicationList {
		t.EncryptedClientHello.configsMu.RLock()
		// this publication is either configured for specific ECH configs,
		// or we just use an implied default of all ECH configs
		var echCfgList echConfigList
		var configIDs []uint8 // TODO: use IDs or the outer names?
		if publication.Configs == nil {
			// by default, publish all configs
			for _, configs := range t.EncryptedClientHello.configs {
				echCfgList = append(echCfgList, configs...)
				for _, c := range configs {
					configIDs = append(configIDs, c.ConfigID)
				}
			}
		} else {
			for _, cfgOuterName := range publication.Configs {
				if cfgList, ok := t.EncryptedClientHello.configs[cfgOuterName]; ok {
					echCfgList = append(echCfgList, cfgList...)
					for _, c := range cfgList {
						configIDs = append(configIDs, c.ConfigID)
					}
				}
			}
		}
		t.EncryptedClientHello.configsMu.RUnlock()

		// marshal the ECH config list as binary for publication
		echCfgListBin, err := echCfgList.MarshalBinary()
		if err != nil {
			return fmt.Errorf("marshaling ECH config list: %v", err)
		}

		// now we have our list of ECH configs to publish and the inner names
		// to publish for (i.e. the names being protected); iterate each publisher
		// and do the publish for any config+name that needs a publish
		for _, publisher := range publication.publishers {
			publisherKey := publisher.PublisherKey()

			// by default, publish for all (non-outer) server names, unless
			// a specific list of names is configured
			var serverNamesSet map[string]struct{}
			if publication.Domains == nil {
				serverNamesSet = make(map[string]struct{}, len(t.serverNames))
				for name := range t.serverNames {
					serverNamesSet[name] = struct{}{}
				}
			} else {
				serverNamesSet = make(map[string]struct{}, len(publication.Domains))
				for _, name := range publication.Domains {
					serverNamesSet[name] = struct{}{}
				}
			}

			// remove any domains from the set which have already had all configs in the
			// list published by this publisher, to avoid always re-publishing unnecessarily
			for configuredInnerName := range serverNamesSet {
				allConfigsPublished := true
				for _, cfg := range echCfgList {
					// TODO: Potentially utilize the timestamp (map value) for recent-enough publication, instead of just checking for existence
					if _, ok := cfg.meta.Publications[publisherKey][configuredInnerName]; !ok {
						allConfigsPublished = false
						break
					}
				}
				if allConfigsPublished {
					delete(serverNamesSet, configuredInnerName)
				}
			}

			// if all the (inner) domains have had this ECH config list published
			// by this publisher, then try the next publication config
			if len(serverNamesSet) == 0 {
				logger.Debug("ECH config list already published by publisher for associated domains (or no domains to publish for)",
					zap.Uint8s("config_ids", configIDs),
					zap.String("publisher", publisherKey))
				continue
			}

			// convert the set of names to a slice
			dnsNamesToPublish := make([]string, 0, len(serverNamesSet))
			for name := range serverNamesSet {
				dnsNamesToPublish = append(dnsNamesToPublish, name)
			}

			logger.Debug("publishing ECH config list",
				zap.String("publisher", publisherKey),
				zap.Strings("domains", dnsNamesToPublish),
				zap.Uint8s("config_ids", configIDs))

			// publish this ECH config list with this publisher
			pubTime := time.Now()
			err := publisher.PublishECHConfigList(t.ctx, dnsNamesToPublish, echCfgListBin)

			var publishErrs PublishECHConfigListErrors
			if errors.As(err, &publishErrs) {
				// at least a partial failure, maybe a complete failure, but we can
				// log each error by domain
				for innerName, domainErr := range publishErrs {
					logger.Error("failed to publish ECH configuration list",
						zap.String("publisher", publisherKey),
						zap.String("domain", innerName),
						zap.Uint8s("config_ids", configIDs),
						zap.Error(domainErr))
				}
			} else if err != nil {
				// generic error; assume the entire thing failed, I guess
				logger.Error("failed publishing ECH configuration list",
					zap.String("publisher", publisherKey),
					zap.Strings("domains", dnsNamesToPublish),
					zap.Uint8s("config_ids", configIDs),
					zap.Error(err))
			}

			if err == nil || (len(publishErrs) > 0 && len(publishErrs) < len(dnsNamesToPublish)) {
				// if publication for at least some domains succeeded, we should update our publication
				// state for those domains to avoid unnecessarily republishing every time
				someAll := "all"
				if len(publishErrs) > 0 {
					someAll = "some"
				}
				// make a list of names that published successfully with this publisher
				// so that we update only their state in storage, not the failed ones
				var successNames []string
				for _, name := range dnsNamesToPublish {
					if _, ok := publishErrs[name]; !ok {
						successNames = append(successNames, name)
					}
				}
				logger.Info("successfully published ECH configuration list for "+someAll+" domains",
					zap.String("publisher", publisherKey),
					zap.Strings("domains", successNames),
					zap.Uint8s("config_ids", configIDs))

				for _, cfg := range echCfgList {
					if cfg.meta.Publications == nil {
						cfg.meta.Publications = make(publicationHistory)
					}
					if _, ok := cfg.meta.Publications[publisherKey]; !ok {
						cfg.meta.Publications[publisherKey] = make(map[string]time.Time)
					}
					for _, name := range successNames {
						cfg.meta.Publications[publisherKey][name] = pubTime
					}
					metaBytes, err := json.Marshal(cfg.meta)
					if err != nil {
						return fmt.Errorf("marshaling ECH config metadata: %v", err)
					}
					if err := t.ctx.Storage().Store(t.ctx, echMetaKey(cfg.ConfigID), metaBytes); err != nil {
						return fmt.Errorf("storing updated ECH config metadata: %v", err)
					}
				}
			} else {
				logger.Error("all domains failed to publish ECH configuration list (see earlier errors)",
					zap.String("publisher", publisherKey),
					zap.Strings("domains", dnsNamesToPublish),
					zap.Uint8s("config_ids", configIDs))
			}
		}
	}

	return nil
}

// loadECHConfig loads the config from storage with the given configID.
// An error is not actually returned in some cases the config fails to
// load because in some cases it just means the config ID folder has
// been cleaned up in storage, maybe due to an incomplete set of keys
// or corrupted contents; in any case, the only rectification is to
// delete it and make new keys (an error IS returned if deleting the
// corrupted keys fails, for example). Check the returned echConfig for
// non-nil privKeyBin and configBin values before using.
func loadECHConfig(ctx caddy.Context, configID string) (echConfig, error) {
	storage := ctx.Storage()
	logger := ctx.Logger()

	cfgIDKey := path.Join(echConfigsKey, configID)
	keyKey := path.Join(cfgIDKey, "key.bin")
	configKey := path.Join(cfgIDKey, "config.bin")
	metaKey := path.Join(cfgIDKey, "meta.json")

	// if loading anything fails, might as well delete this folder and free up
	// the config ID; spec is designed to rotate configs frequently anyway
	// (I consider it a more serious error if we can't clean up the folder,
	// since leaving stray storage keys is confusing)
	privKeyBytes, err := storage.Load(ctx, keyKey)
	if err != nil {
		delErr := storage.Delete(ctx, cfgIDKey)
		if delErr != nil {
			return echConfig{}, fmt.Errorf("error loading private key (%v) and cleaning up parent storage key %s: %v", err, cfgIDKey, delErr)
		}
		logger.Warn("could not load ECH private key; deleting its config folder",
			zap.String("config_id", configID),
			zap.Error(err))
		return echConfig{}, nil
	}
	echConfigBytes, err := storage.Load(ctx, configKey)
	if err != nil {
		delErr := storage.Delete(ctx, cfgIDKey)
		if delErr != nil {
			return echConfig{}, fmt.Errorf("error loading ECH config (%v) and cleaning up parent storage key %s: %v", err, cfgIDKey, delErr)
		}
		logger.Warn("could not load ECH config; deleting its config folder",
			zap.String("config_id", configID),
			zap.Error(err))
		return echConfig{}, nil
	}
	var cfg echConfig
	if err := cfg.UnmarshalBinary(echConfigBytes); err != nil {
		delErr := storage.Delete(ctx, cfgIDKey)
		if delErr != nil {
			return echConfig{}, fmt.Errorf("error loading ECH config (%v) and cleaning up parent storage key %s: %v", err, cfgIDKey, delErr)
		}
		logger.Warn("could not load ECH config; deleted its config folder",
			zap.String("config_id", configID),
			zap.Error(err))
		return echConfig{}, nil
	}
	metaBytes, err := storage.Load(ctx, metaKey)
	if errors.Is(err, fs.ErrNotExist) {
		logger.Warn("ECH config metadata file missing; will recreate at next publication",
			zap.String("config_id", configID),
			zap.Error(err))
	} else if err != nil {
		delErr := storage.Delete(ctx, cfgIDKey)
		if delErr != nil {
			return echConfig{}, fmt.Errorf("error loading ECH config metadata (%v) and cleaning up parent storage key %s: %v", err, cfgIDKey, delErr)
		}
		logger.Warn("could not load ECH config metadata; deleted its folder",
			zap.String("config_id", configID),
			zap.Error(err))
		return echConfig{}, nil
	}
	var meta echConfigMeta
	if len(metaBytes) > 0 {
		if err := json.Unmarshal(metaBytes, &meta); err != nil {
			// even though it's just metadata, reset the whole config since we can't reliably maintain it
			delErr := storage.Delete(ctx, cfgIDKey)
			if delErr != nil {
				return echConfig{}, fmt.Errorf("error decoding ECH metadata (%v) and cleaning up parent storage key %s: %v", err, cfgIDKey, delErr)
			}
			logger.Warn("could not JSON-decode ECH metadata; deleted its config folder",
				zap.String("config_id", configID),
				zap.Error(err))
			return echConfig{}, nil
		}
	}

	cfg.privKeyBin = privKeyBytes
	cfg.configBin = echConfigBytes
	cfg.meta = meta

	return cfg, nil
}

func generateAndStoreECHConfig(ctx caddy.Context, publicName string) (echConfig, error) {
	// Go currently has very strict requirements for server-side ECH configs,
	// to quote the Go 1.24 godoc (with typos of AEAD IDs corrected):
	//
	// "Config should be a marshalled ECHConfig associated with PrivateKey. This
	// must match the config provided to clients byte-for-byte. The config
	// should only specify the DHKEM(X25519, HKDF-SHA256) KEM ID (0x0020), the
	// HKDF-SHA256 KDF ID (0x0001), and a subset of the following AEAD IDs:
	// AES-128-GCM (0x0001), AES-256-GCM (0x0002), ChaCha20Poly1305 (0x0003)."
	//
	// So we need to be sure we generate a config within these parameters
	// so the Go TLS server can use it.

	// generate a key pair
	const kemChoice = hpke.KEM_X25519_HKDF_SHA256
	publicKey, privateKey, err := kemChoice.Scheme().GenerateKeyPair()
	if err != nil {
		return echConfig{}, err
	}

	// find an available config ID
	configID, err := newECHConfigID(ctx)
	if err != nil {
		return echConfig{}, fmt.Errorf("generating unique config ID: %v", err)
	}

	echCfg := echConfig{
		PublicKey:     publicKey,
		Version:       draftTLSESNI25,
		ConfigID:      configID,
		RawPublicName: publicName,
		KEMID:         kemChoice,
		CipherSuites: []hpkeSymmetricCipherSuite{
			{
				KDFID:  hpke.KDF_HKDF_SHA256,
				AEADID: hpke.AEAD_AES128GCM,
			},
			{
				KDFID:  hpke.KDF_HKDF_SHA256,
				AEADID: hpke.AEAD_AES256GCM,
			},
			{
				KDFID:  hpke.KDF_HKDF_SHA256,
				AEADID: hpke.AEAD_ChaCha20Poly1305,
			},
		},
	}
	meta := echConfigMeta{
		Created: time.Now(),
	}

	privKeyBytes, err := privateKey.MarshalBinary()
	if err != nil {
		return echConfig{}, fmt.Errorf("marshaling ECH private key: %v", err)
	}
	echConfigBytes, err := echCfg.MarshalBinary()
	if err != nil {
		return echConfig{}, fmt.Errorf("marshaling ECH config: %v", err)
	}
	metaBytes, err := json.Marshal(meta)
	if err != nil {
		return echConfig{}, fmt.Errorf("marshaling ECH config metadata: %v", err)
	}

	parentKey := path.Join(echConfigsKey, strconv.Itoa(int(configID)))
	keyKey := path.Join(parentKey, "key.bin")
	configKey := path.Join(parentKey, "config.bin")
	metaKey := path.Join(parentKey, "meta.json")

	if err := ctx.Storage().Store(ctx, keyKey, privKeyBytes); err != nil {
		return echConfig{}, fmt.Errorf("storing ECH private key: %v", err)
	}
	if err := ctx.Storage().Store(ctx, configKey, echConfigBytes); err != nil {
		return echConfig{}, fmt.Errorf("storing ECH config: %v", err)
	}
	if err := ctx.Storage().Store(ctx, metaKey, metaBytes); err != nil {
		return echConfig{}, fmt.Errorf("storing ECH config metadata: %v", err)
	}

	echCfg.privKeyBin = privKeyBytes
	echCfg.configBin = echConfigBytes // this contains the public key
	echCfg.meta = meta

	return echCfg, nil
}

// ECH represents an Encrypted ClientHello configuration.
//
// EXPERIMENTAL: Subject to change.
type ECHConfiguration struct {
	// The public server name (SNI) that will be used in the outer ClientHello.
	// This should be a domain name for which this server is authoritative,
	// because Caddy will try to provision a certificate for this name. As an
	// outer SNI, it is never used for application data (HTTPS, etc.), but it
	// is necessary for enabling clients to connect securely in some cases.
	// If this field is empty or missing, or if Caddy cannot get a certificate
	// for this domain (e.g. the domain's DNS records do not point to this server),
	// client reliability becomes brittle, and you risk coercing clients to expose
	// true server names in plaintext, which compromises both the privacy of the
	// server and makes clients more vulnerable.
	PublicName string `json:"public_name"`
}

// ECHPublication configures publication of ECH config(s). It pairs a list
// of ECH configs with the list of domains they are assigned to protect, and
// describes how to publish those configs for those domains.
//
// Most servers will have only a single publication config, unless their
// domains are spread across multiple DNS providers or require different
// methods of publication.
//
// EXPERIMENTAL: Subject to change.
type ECHPublication struct {
	// The list of ECH configurations to publish, identified by public name.
	// If not set, all configs will be included for publication by default.
	//
	// It is generally advised to maximize the size of your anonymity set,
	// which implies using as few public names as possible for your sites.
	// Usually, only a single public name is used to protect all the sites
	// for a server
	//
	// EXPERIMENTAL: This field may be renamed or have its structure changed.
	Configs []string `json:"configs,omitempty"`

	// The list of ("inner") domain names which are protected with the associated
	// ECH configurations.
	//
	// If not set, all server names registered with the TLS module will be
	// added to this list implicitly. (This registration is done automatically
	// by other Caddy apps that use the TLS module. They should register their
	// configured server names for this purpose. For example, the HTTP server
	// registers the hostnames for which it applies automatic HTTPS. This is
	// not something you, the user, have to do.) Most servers
	//
	// Names in this list should not appear in any other publication config
	// object with the same publishers, since the publications will likely
	// overwrite each other.
	//
	// NOTE: In order to publish ECH configs for domains configured for
	// On-Demand TLS that are not explicitly enumerated elsewhere in the
	// config, those domain names will have to be listed here. The only
	// time Caddy knows which domains it is serving with On-Demand TLS is
	// handshake-time, which is too late for publishing ECH configs; it
	// means the first connections would not protect the server names,
	// revealing that information to observers, and thus defeating the
	// purpose of ECH. Hence the need to list them here so Caddy can
	// proactively publish ECH configs before clients connect with those
	// server names in plaintext.
	Domains []string `json:"domains,omitempty"`

	// How to publish the ECH configurations so clients can know to use
	// ECH to connect more securely to the server.
	PublishersRaw caddy.ModuleMap `json:"publishers,omitempty" caddy:"namespace=tls.ech.publishers"`
	publishers    []ECHPublisher
}

// ECHDNSProvider can service DNS entries for ECH purposes.
type ECHDNSProvider interface {
	libdns.RecordGetter
	libdns.RecordSetter
}

// ECHDNSPublisher configures how to publish an ECH configuration to
// DNS records for the specified domains.
//
// EXPERIMENTAL: Subject to change.
type ECHDNSPublisher struct {
	// The DNS provider module which will establish the HTTPS record(s).
	ProviderRaw json.RawMessage `json:"provider,omitempty" caddy:"namespace=dns.providers inline_key=name"`
	provider    ECHDNSProvider

	logger *zap.Logger
}

// CaddyModule returns the Caddy module information.
func (ECHDNSPublisher) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "tls.ech.publishers.dns",
		New: func() caddy.Module { return new(ECHDNSPublisher) },
	}
}

func (dnsPub *ECHDNSPublisher) Provision(ctx caddy.Context) error {
	dnsProvMod, err := ctx.LoadModule(dnsPub, "ProviderRaw")
	if err != nil {
		return fmt.Errorf("loading ECH DNS provider module: %v", err)
	}
	prov, ok := dnsProvMod.(ECHDNSProvider)
	if !ok {
		return fmt.Errorf("ECH DNS provider module is not an ECH DNS Provider: %v", err)
	}
	dnsPub.provider = prov
	dnsPub.logger = ctx.Logger()
	return nil
}

// PublisherKey returns the name of the DNS provider module.
// We intentionally omit specific provider configuration (or a hash thereof,
// since the config is likely sensitive, potentially containing an API key)
// because it is unlikely that specific configuration, such as an API key,
// is relevant to unique key use as an ECH config publisher.
func (dnsPub ECHDNSPublisher) PublisherKey() string {
	return string(dnsPub.provider.(caddy.Module).CaddyModule().ID)
}

// PublishECHConfigList publishes the given ECH config list (as binary) to the given DNS names.
// If there is an error, it may be of type PublishECHConfigListErrors, detailing
// potentially multiple errors keyed by associated innerName.
func (dnsPub *ECHDNSPublisher) PublishECHConfigList(ctx context.Context, innerNames []string, configListBin []byte) error {
	nameservers := certmagic.RecursiveNameservers(nil) // TODO: we could make resolvers configurable

	errs := make(PublishECHConfigListErrors)

nextName:
	for _, domain := range innerNames {
		zone, err := certmagic.FindZoneByFQDN(ctx, dnsPub.logger, domain, nameservers)
		if err != nil {
			errs[domain] = fmt.Errorf("could not determine zone for domain: %w (domain=%s nameservers=%v)", err, domain, nameservers)
			continue
		}

		relName := libdns.RelativeName(domain+".", zone)

		// get existing records for this domain; we need to make sure another
		// record exists for it so we don't accidentally trample a wildcard; we
		// also want to get any HTTPS record that may already exist for it so
		// we can augment the ech SvcParamKey with any other existing SvcParams
		recs, err := dnsPub.provider.GetRecords(ctx, zone)
		if err != nil {
			errs[domain] = fmt.Errorf("unable to get existing DNS records to publish ECH data to HTTPS DNS record: %w", err)
			continue
		}
		var httpsRec libdns.ServiceBinding
		var nameHasExistingRecord bool
		for _, rec := range recs {
			rr := rec.RR()
			if rr.Name == relName {
				// CNAME records are exclusive of all other records, so we cannot publish an HTTPS
				// record for a domain that is CNAME'd. See #6922.
				if rr.Type == "CNAME" {
					dnsPub.logger.Warn("domain has CNAME record, so unable to publish ECH data to HTTPS record",
						zap.String("domain", domain),
						zap.String("cname_value", rr.Data))
					continue nextName
				}
				nameHasExistingRecord = true
				if svcb, ok := rec.(libdns.ServiceBinding); ok && svcb.Scheme == "https" {
					if svcb.Target == "" || svcb.Target == "." {
						httpsRec = svcb
						break
					}
				}
			}
		}
		if !nameHasExistingRecord {
			// Turns out if you publish a DNS record for a name that doesn't have any DNS record yet,
			// any wildcard records won't apply for the name anymore, meaning if a wildcard A/AAAA record
			// is used to resolve the domain to a server, publishing an HTTPS record could break resolution!
			// In theory, this should be a non-issue, at least for A/AAAA records, if the HTTPS record
			// includes ipv[4|6]hint SvcParamKeys,
			dnsPub.logger.Warn("domain does not have any existing records, so skipping publication of HTTPS record",
				zap.String("domain", domain),
				zap.String("relative_name", relName),
				zap.String("zone", zone))
			continue
		}
		params := httpsRec.Params
		if params == nil {
			params = make(libdns.SvcParams)
		}

		// overwrite only the "ech" SvcParamKey
		params["ech"] = []string{base64.StdEncoding.EncodeToString(configListBin)}

		// publish record
		_, err = dnsPub.provider.SetRecords(ctx, zone, []libdns.Record{
			libdns.ServiceBinding{
				// HTTPS and SVCB RRs: RFC 9460 (https://www.rfc-editor.org/rfc/rfc9460)
				Scheme:   "https",
				Name:     relName,
				TTL:      5 * time.Minute, // TODO: low hard-coded value only temporary; change to a higher value once more field-tested and key rotation is implemented
				Priority: 2,               // allows a manual override with priority 1
				Target:   ".",
				Params:   params,
			},
		})
		if err != nil {
			errs[domain] = fmt.Errorf("unable to publish ECH data to HTTPS DNS record: %w (zone=%s dns_record_name=%s)", err, zone, relName)
			continue
		}
	}

	if len(errs) > 0 {
		return errs
	}
	return nil
}

// echConfig represents an ECHConfig from the specification,
// [draft-ietf-tls-esni-22](https://www.ietf.org/archive/id/draft-ietf-tls-esni-22.html).
type echConfig struct {
	// "The version of ECH for which this configuration is used.
	// The version is the same as the code point for the
	// encrypted_client_hello extension. Clients MUST ignore any
	// ECHConfig structure with a version they do not support."
	Version uint16

	// The "length" and "contents" fields defined next in the
	// structure are implicitly taken care of by cryptobyte
	// when encoding the following fields:

	// HpkeKeyConfig fields:
	ConfigID     uint8
	KEMID        hpke.KEM
	PublicKey    kem.PublicKey
	CipherSuites []hpkeSymmetricCipherSuite

	// ECHConfigContents fields:
	MaxNameLength uint8
	RawPublicName string
	RawExtensions []byte

	// these fields are not part of the spec, but are here for
	// our use when setting up TLS servers or maintenance
	configBin  []byte
	privKeyBin []byte
	meta       echConfigMeta
}

func (echCfg echConfig) MarshalBinary() ([]byte, error) {
	var b cryptobyte.Builder
	if err := echCfg.marshalBinary(&b); err != nil {
		return nil, err
	}
	return b.Bytes()
}

// UnmarshalBinary decodes the data back into an ECH config.
//
// Borrowed from github.com/OmarTariq612/goech with modifications.
// Original code: Copyright (c) 2023 Omar Tariq AbdEl-Raziq
func (echCfg *echConfig) UnmarshalBinary(data []byte) error {
	var content cryptobyte.String
	b := cryptobyte.String(data)

	if !b.ReadUint16(&echCfg.Version) {
		return errInvalidLen
	}
	if echCfg.Version != draftTLSESNI25 {
		return fmt.Errorf("supported version must be %d: got %d", draftTLSESNI25, echCfg.Version)
	}

	if !b.ReadUint16LengthPrefixed(&content) || !b.Empty() {
		return errInvalidLen
	}

	var t cryptobyte.String
	var pk []byte

	if !content.ReadUint8(&echCfg.ConfigID) ||
		!content.ReadUint16((*uint16)(&echCfg.KEMID)) ||
		!content.ReadUint16LengthPrefixed(&t) ||
		!t.ReadBytes(&pk, len(t)) ||
		!content.ReadUint16LengthPrefixed(&t) ||
		len(t)%4 != 0 /* the length of (KDFs and AEADs) must be divisible by 4 */ {
		return errInvalidLen
	}

	if !echCfg.KEMID.IsValid() {
		return fmt.Errorf("invalid KEM ID: %d", echCfg.KEMID)
	}

	var err error
	if echCfg.PublicKey, err = echCfg.KEMID.Scheme().UnmarshalBinaryPublicKey(pk); err != nil {
		return fmt.Errorf("parsing public_key: %w", err)
	}

	echCfg.CipherSuites = echCfg.CipherSuites[:0]

	for !t.Empty() {
		var hpkeKDF, hpkeAEAD uint16
		if !t.ReadUint16(&hpkeKDF) || !t.ReadUint16(&hpkeAEAD) {
			// we have already checked that the length is divisible by 4
			panic("this must not happen")
		}
		if !hpke.KDF(hpkeKDF).IsValid() {
			return fmt.Errorf("invalid KDF ID: %d", hpkeKDF)
		}
		if !hpke.AEAD(hpkeAEAD).IsValid() {
			return fmt.Errorf("invalid AEAD ID: %d", hpkeAEAD)
		}
		echCfg.CipherSuites = append(echCfg.CipherSuites, hpkeSymmetricCipherSuite{
			KDFID:  hpke.KDF(hpkeKDF),
			AEADID: hpke.AEAD(hpkeAEAD),
		})
	}

	var rawPublicName []byte
	if !content.ReadUint8(&echCfg.MaxNameLength) ||
		!content.ReadUint8LengthPrefixed(&t) ||
		!t.ReadBytes(&rawPublicName, len(t)) ||
		!content.ReadUint16LengthPrefixed(&t) ||
		!t.ReadBytes(&echCfg.RawExtensions, len(t)) ||
		!content.Empty() {
		return errInvalidLen
	}
	echCfg.RawPublicName = string(rawPublicName)

	return nil
}

var errInvalidLen = errors.New("invalid length")

// marshalBinary writes this config to the cryptobyte builder. If there is an error,
// it will occur before any writes have happened.
func (echCfg echConfig) marshalBinary(b *cryptobyte.Builder) error {
	pk, err := echCfg.PublicKey.MarshalBinary()
	if err != nil {
		return err
	}
	if l := len(echCfg.RawPublicName); l == 0 || l > 255 {
		return fmt.Errorf("public name length (%d) must be in the range 1-255", l)
	}

	b.AddUint16(echCfg.Version)
	b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) { // "length" field
		b.AddUint8(echCfg.ConfigID)
		b.AddUint16(uint16(echCfg.KEMID))
		b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
			b.AddBytes(pk)
		})
		b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
			for _, cs := range echCfg.CipherSuites {
				b.AddUint16(uint16(cs.KDFID))
				b.AddUint16(uint16(cs.AEADID))
			}
		})
		b.AddUint8(uint8(min(len(echCfg.RawPublicName)+16, 255)))
		b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) {
			b.AddBytes([]byte(echCfg.RawPublicName))
		})
		b.AddUint16LengthPrefixed(func(child *cryptobyte.Builder) {
			child.AddBytes(echCfg.RawExtensions)
		})
	})

	return nil
}

type hpkeSymmetricCipherSuite struct {
	KDFID  hpke.KDF
	AEADID hpke.AEAD
}

type echConfigList []echConfig

func (cl echConfigList) MarshalBinary() ([]byte, error) {
	var b cryptobyte.Builder
	var err error

	// the list's length prefixes the list, as with most opaque values
	b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
		for _, cfg := range cl {
			if err = cfg.marshalBinary(b); err != nil {
				break
			}
		}
	})
	if err != nil {
		return nil, err
	}

	return b.Bytes()
}

func newECHConfigID(ctx caddy.Context) (uint8, error) {
	// uint8 can be 0-255 inclusive
	const uint8Range = 256

	// avoid repeating storage checks
	tried := make([]bool, uint8Range)

	// Try to find an available number with random rejection sampling;
	// i.e. choose a random number and see if it's already taken.
	// The hard limit on how many times we try to find an available
	// number is flexible... in theory, assuming uniform distribution,
	// 256 attempts should make each possible value show up exactly
	// once, but obviously that won't be the case. We can try more
	// times to try to ensure that every number gets a chance, which
	// is especially useful if few are available, or we can lower it
	// if we assume we should have found an available value by then
	// and want to limit runtime; for now I choose the middle ground
	// and just try as many times as there are possible values.
	for i := 0; i < uint8Range && ctx.Err() == nil; i++ {
		num := uint8(weakrand.N(uint8Range)) //nolint:gosec

		// don't try the same number a second time
		if tried[num] {
			continue
		}
		tried[num] = true

		// check to see if any of the subkeys use this config ID
		numStr := strconv.Itoa(int(num))
		trialPath := path.Join(echConfigsKey, numStr)
		if ctx.Storage().Exists(ctx, trialPath) {
			continue
		}

		return num, nil
	}

	if err := ctx.Err(); err != nil {
		return 0, err
	}

	return 0, fmt.Errorf("depleted attempts to find an available config_id")
}

// ECHPublisher is an interface for publishing ECHConfigList values
// so that they can be used by clients.
type ECHPublisher interface {
	// Returns a key that is unique to this publisher and its configuration.
	// A publisher's ID combined with its config is a valid key.
	// It is used to prevent duplicating publications.
	PublisherKey() string

	// Publishes the ECH config list (as binary) for the given innerNames. Some
	// publishers may not need a list of inner/protected names, and can ignore the
	// argument; most, however, will want to use it to know which inner names are
	// to be associated with the given ECH config list.
	//
	// Implementations should return an error of type PublishECHConfigListErrors
	// when relevant to key errors to their associated innerName, but should never
	// return a non-nil PublishECHConfigListErrors when its length is 0.
	PublishECHConfigList(ctx context.Context, innerNames []string, echConfigList []byte) error
}

// PublishECHConfigListErrors is returned by ECHPublishers to describe one or more
// errors publishing an ECH config list from PublishECHConfigList. A non-nil, empty
// value of this type should never be returned.
// nolint:errname // The linter wants "Error" convention, but this is a multi-error type.
type PublishECHConfigListErrors map[string]error

func (p PublishECHConfigListErrors) Error() string {
	var sb strings.Builder
	for innerName, err := range p {
		if sb.Len() > 0 {
			sb.WriteString("; ")
		}
		sb.WriteString(innerName)
		sb.WriteString(": ")
		sb.WriteString(err.Error())
	}
	return sb.String()
}

type echConfigMeta struct {
	Created      time.Time          `json:"created"`
	Replaced     time.Time          `json:"replaced,omitzero"`
	Publications publicationHistory `json:"publications"`
}

func echMetaKey(configID uint8) string {
	return path.Join(echConfigsKey, strconv.Itoa(int(configID)), "meta.json")
}

// publicationHistory is a map of publisher key to
// map of inner name to timestamp
type publicationHistory map[string]map[string]time.Time

// echStorageLockName is the name of the storage lock to sync ECH updates.
const echStorageLockName = "ech_rotation"

// The key prefix when putting ECH configs in storage. After this
// comes the config ID.
const echConfigsKey = "ech/configs"

// https://www.ietf.org/archive/id/draft-ietf-tls-esni-25.html
const draftTLSESNI25 = 0xfe0d

// Interface guard
var _ ECHPublisher = (*ECHDNSPublisher)(nil)
