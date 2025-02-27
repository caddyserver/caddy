package caddytls

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	weakrand "math/rand/v2"
	"path"
	"strconv"
	"strings"
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
	caddy.RegisterModule(ECHDNSPublisherList{})
}

// ECH enables Encrypted ClientHello (ECH) and configures its management.
//
// Note that, as of Caddy 2.10 (~March 2025), ECH keys are not automatically
// rotated due to a limitation in the Go standard library (see
// https://github.com/golang/go/issues/71920). This should be resolved when
// Go 1.25 is released (~Aug. 2025), and Caddy will be updated to automatically
// rotate ECH keys/configs at that point.
//
// EXPERIMENTAL: Subject to change.
type ECH struct {
	// The list of ECH configurations for which to automatically generate
	// and rotate keys. At least one is required to enable ECH.
	Configs []ECHConfiguration `json:"configs,omitempty"`

	// Publication describes ways to publish ECH configs for clients to
	// discover and use. Without publication, most clients will not use
	// ECH at all, and those that do will suffer degraded performance.
	//
	// Most major browsers support ECH by way of publication to HTTPS
	// DNS RRs. (This also typically requires that they use DoH or DoT.)
	Publication []*ECHPublication `json:"publication,omitempty"`

	// map of public_name to list of configs ordered by date (newest first)
	configs map[string][]echConfig
}

// Provision loads or creates ECH configs and returns outer names (for certificate
// management), but does not publish any ECH configs. The DNS module is used as
// a default for later publishing if needed.
func (ech *ECH) Provision(ctx caddy.Context) ([]string, error) {
	// TODO: Provisioning this should be made atomic using the storage backend; currently, it
	// is not properly synced if distributed instances are initializing simultaneously...
	storage := ctx.Storage()

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
		ech.configs[cfg.RawPublicName] = append(ech.configs[cfg.RawPublicName], cfg)
		outerNames = append(outerNames, cfg.RawPublicName)
	}

	// all existing configs are now loaded; see if we need to make any new ones
	// based on the input configuration

	for _, cfg := range ech.Configs {
		publicName := strings.ToLower(strings.TrimSpace(cfg.OuterSNI))

		// if no config is loaded for this public name, we need to create one
		if list, ok := ech.configs[publicName]; !ok || len(list) == 0 {
			echCfg, err := generateAndStoreECHConfig(ctx, publicName)
			if err != nil {
				return nil, err
			}
			ech.configs[publicName] = append(ech.configs[publicName], echCfg)
			outerNames = append(outerNames, publicName)
		}
	}

	// set up publication modules
	for i, pub := range ech.Publication {
		mods, err := ctx.LoadModule(pub, "PublishersRaw")
		if err != nil {
			return nil, fmt.Errorf("loading ECH publication modules: %v", err)
		}
		for _, modIface := range mods.(map[string]any) {
			ech.Publication[i].publishers = append(ech.Publication[i].publishers, modIface.(ECHPublisher))
		}
	}

	return outerNames, nil
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
	if err != nil {
		delErr := storage.Delete(ctx, cfgIDKey)
		if delErr != nil {
			return echConfig{}, fmt.Errorf("error loading ECH metadata (%v) and cleaning up parent storage key %s: %v", err, cfgIDKey, delErr)
		}
		logger.Warn("could not load ECH metadata; deleted its config folder",
			zap.String("config_id", configID),
			zap.Error(err))
		return echConfig{}, nil
	}
	var meta echConfigMeta
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
		Version:       draftTLSESNI22,
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
	// The public server name that will be used in the outer ClientHello. This
	// should be a domain name for which this server is authoritative, because
	// Caddy will try to provision a certificate for this name. As an outer
	// SNI, it is never used for application data (HTTPS, etc.), but it is
	// necessary for securely reconciling inconsistent client state without
	// breakage and brittleness.
	OuterSNI string `json:"outer_sni,omitempty"`
}

// ECHPublication configures publication of ECH config(s).
type ECHPublication struct {
	// TODO: Should these first two fields be called outer_sni and inner_sni ?

	// The list of ECH configurations to publish, identified by public name.
	// If not set, all configs will be included for publication by default.
	Configs []string `json:"configs,omitempty"`

	// The list of domain names which are protected with the associated ECH
	// configurations ("inner names"). Not all publishers may require this
	// information, but some, like the DNS publisher, do. (The DNS publisher,
	// for example, needs to know for which domain(s) to create DNS records.)
	//
	// If not set, all server names registered with the TLS module will be
	// added to this list implicitly. (Other Caddy apps that use the TLS
	// module automatically register their configured server names for this
	// purpose. For example, the HTTP server registers the hostnames for
	// which it applies automatic HTTPS.)
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
	DNSNames []string `json:"dns_names,omitempty"`

	// How to publish the ECH configurations so clients can know to use them.
	// Note that ECH configs are only published when they are newly created,
	// so adding or changing publishers after the fact will have no effect
	// with existing ECH configs. The next time a config is generated (including
	// when a key is rotated), the current publication modules will be utilized.
	PublishersRaw caddy.ModuleMap `json:"publishers,omitempty" caddy:"namespace=tls.ech.publishers"`
	publishers    []ECHPublisher
}

// ECHDNSPublisher configures how to publish an ECH configuration to
// DNS records for the specified domains.
//
// EXPERIMENTAL: Subject to change.
type ECHDNSPublisher struct {
	// The DNS provider module which will establish the HTTPS record(s).
	ProviderRaw json.RawMessage `json:"provider,omitempty" caddy:"namespace=dns.providers inline_key=name"`
	provider    libdns.RecordSetter

	logger *zap.Logger
}

// ECHDNSPublisherList is a list of DNS publication configs,
// so that different groups of domain names may have ECH configs
// published across different DNS providers, if necessary.
//
// EXPERIMENTAL: Subject to change.
//
// TODO: Does it make sense to have multiple? Do we really need to (is it even possible to need to) set DNS records for a group of names across more than 1 provider?
// TODO: Based on a discussion on social media, it sounds like only one would be necessary.
type ECHDNSPublisherList []*ECHDNSPublisher

// CaddyModule returns the Caddy module information.
func (ECHDNSPublisherList) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "tls.ech.publishers.dns",
		New: func() caddy.Module { return new(ECHDNSPublisherList) },
	}
}

func (dnsPubList ECHDNSPublisherList) Provision(ctx caddy.Context) error {
	for i := range dnsPubList {
		dnsProvMod, err := ctx.LoadModule(dnsPubList[i], "ProviderRaw")
		if err != nil {
			return fmt.Errorf("loading ECH DNS provider module: %v", err)
		}
		recSet, ok := dnsProvMod.(libdns.RecordSetter)
		if !ok {
			return fmt.Errorf("ECH DNS provider module is not a RecordSetter: %v", err)
		}
		dnsPubList[i].provider = recSet
		dnsPubList[i].logger = ctx.Logger()
	}
	return nil
}

func (dnsPubList ECHDNSPublisherList) PublishECHConfigList(ctx context.Context, innerNames []string, echConfigList []byte) error {
	for i, pub := range dnsPubList {
		if err := pub.PublishECHConfigList(ctx, innerNames, echConfigList); err != nil {
			return fmt.Errorf("publisher %d: %v", i, err)
		}
	}
	return nil
}

func (dnsPub *ECHDNSPublisher) PublishECHConfigList(ctx context.Context, innerNames []string, configListBin []byte) error {
	nameservers := certmagic.RecursiveNameservers(nil) // TODO: we could make resolvers configurable

	for _, domain := range innerNames {
		zone, err := certmagic.FindZoneByFQDN(ctx, dnsPub.logger, domain, nameservers)
		if err != nil {
			dnsPub.logger.Error("could not determine zone for domain",
				zap.String("domain", domain),
				zap.Error(err))
			continue
		}
		_, err = dnsPub.provider.SetRecords(ctx, zone, []libdns.Record{
			{
				Type:     "HTTPS",
				Name:     libdns.RelativeName(domain+".", zone),
				Priority: 1, // allows a manual override with priority 0
				Target:   ".",
				Value:    echSvcParam(configListBin),
				TTL:      1 * time.Minute, // TODO: for testing only
			},
		})
		if err != nil {
			dnsPub.logger.Error("unable to publish ECH data to HTTPS DNS record",
				zap.String("domain", domain),
				zap.Error(err))
			continue
		}
	}

	return nil
}

// SvcParam syntax is defined in RFC 9460: https://www.rfc-editor.org/rfc/rfc9460#presentation
func echSvcParam(echConfigListBinary []byte) string {
	return fmt.Sprintf(`ech=%q`, base64.StdEncoding.EncodeToString(echConfigListBinary))
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
	if echCfg.Version != draftTLSESNI22 {
		return fmt.Errorf("supported version must be %d: got %d", draftTLSESNI22, echCfg.Version)
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
	PublishECHConfigList(ctx context.Context, innerNames []string, echConfigList []byte) error
}

type echConfigMeta struct {
	Created      time.Time `json:"created"`
	Publications []string  `json:"publications"`
}

// The key prefix when putting ECH configs in storage. After this
// comes the config ID.
const echConfigsKey = "ech/configs"

// https://www.ietf.org/archive/id/draft-ietf-tls-esni-22.html
const draftTLSESNI22 = 0xfe0d

// Interface guard
var _ ECHPublisher = (*ECHDNSPublisherList)(nil)
