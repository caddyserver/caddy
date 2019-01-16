// Package aesnicheck provides a simple check to see if crypto/aes is using
// AES-NI instructions or if the AES transform is being done in software. AES-NI
// is constant-time, which makes it impervious to cache-level timing attacks. For
// security-conscious deployments on public cloud infrastructure (Amazon EC2,
// Google Compute Engine, Microsoft Azure, etc.) this may be critical.
//
// See http://eprint.iacr.org/2014/248 for details on cross-VM timing attacks on
// AES keys.
package aesnicheck
