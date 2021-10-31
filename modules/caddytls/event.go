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
	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyevent"
	"github.com/caddyserver/certmagic"
)

// onEvent translates certmagic events into caddy events
// then dispatches them asynchronously.
func (t *TLS) onEvent(event string, data interface{}) {
	switch event {
	// case "cached_managed_cert", "cached_unmanaged_cert":
	// 	subjectNames, ok := data.([]string)
	// 	if !ok {
	// 		return
	// 	}
	// 	t.event.AsyncDispatch(caddyevent.NewGeneric(
	// 		caddy.ModuleID("tls.event."+event),
	// 		caddyevent.DataMap{"subjectNames": subjectNames},
	// 	))

	// case "tls_handshake_started", "tls_handshake_completed":
	// 	clientHello, ok := data.(*tls.ClientHelloInfo)
	// 	if !ok {
	// 		return
	// 	}
	// 	t.event.AsyncDispatch(NewHandshakeEvent(event, clientHello))

	case "cert_obtained", "cert_renewed", "cert_revoked":
		eventData, ok := data.(certmagic.CertificateEventData)
		if !ok {
			return
		}
		t.event.AsyncDispatch(NewCertEvent(event, eventData))
	}
}

// CertEvent is dispatched when a certificate is obtained, renewed, or revoked.
type CertEvent struct {
	caddyevent.GenericEvent
}

func NewCertEvent(event string, data certmagic.CertificateEventData) *CertEvent {
	certEvent := new(CertEvent)
	certEvent.SetID(caddy.ModuleID("tls.event." + event))
	certEvent.Set("name", data.Name)
	certEvent.Set("issuerKey", data.IssuerKey)
	certEvent.Set("storageKey", data.StorageKey)
	return certEvent
}

func (e CertEvent) GetName() string {
	return e.Get("name").(string)
}

func (e CertEvent) GetIssuerKey() string {
	return e.Get("issuerKey").(string)
}

func (e CertEvent) GetStorageKey() string {
	return e.Get("storageKey").(string)
}

// HandshakeEvent is dispatched when a TLS handshake is started, or is completed.
// type HandshakeEvent struct {
// 	caddyevent.GenericEvent
// }

// func NewHandshakeEvent(event string, clientHello *tls.ClientHelloInfo) *HandshakeEvent {
// 	handshakeEvent := new(HandshakeEvent)
// 	handshakeEvent.SetID(caddy.ModuleID("tls.event." + event))
// 	handshakeEvent.Set("clientHello", clientHello)
// 	return handshakeEvent
// }

// func (e CertEvent) GetClientHello() *tls.ClientHelloInfo {
// 	return e.Get("clientHello").(*tls.ClientHelloInfo)
// }
