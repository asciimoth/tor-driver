package tordriver

import (
	"context"
	"crypto/ecdh"
	"crypto/sha512"
	"encoding/base32"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strings"
)

const (
	onionServiceKeySize        = 64
	clientAuthorizationKeySize = 32
)

var onionBase32 = base32.StdEncoding.WithPadding(base32.NoPadding)

// OnionServiceKey is a Tor v3 expanded Ed25519 private key. It contains a
// little-endian secret scalar followed by the PRF secret. It is not a Go
// crypto/ed25519.PrivateKey and it is not an Ed25519 seed.
type OnionServiceKey struct {
	expanded [onionServiceKeySize]byte
}

// NewOnionServiceKey validates and copies a Tor expanded Ed25519 private key.
func NewOnionServiceKey(expanded []byte) (OnionServiceKey, error) {
	var key OnionServiceKey
	if len(expanded) != onionServiceKeySize {
		return key, fmt.Errorf("tor-driver: onion service key must contain 64 bytes")
	}
	copy(key.expanded[:], expanded)
	if !key.valid() {
		clear(key.expanded[:])
		return OnionServiceKey{}, fmt.Errorf("tor-driver: invalid expanded Ed25519 scalar")
	}
	return key, nil
}

// OnionServiceKeyFromEd25519Seed expands a 32-byte Ed25519 seed into Tor's
// scalar-and-PRF representation. The result cannot be converted back to a
// generic Ed25519 seed.
func OnionServiceKeyFromEd25519Seed(seed []byte) (OnionServiceKey, error) {
	if len(seed) != 32 {
		return OnionServiceKey{}, fmt.Errorf("tor-driver: Ed25519 seed must contain 32 bytes")
	}
	expanded := sha512.Sum512(seed)
	expanded[0] &= 248
	expanded[31] &= 63
	expanded[31] |= 64
	return NewOnionServiceKey(expanded[:])
}

// ParseOnionServiceKey parses the text produced by MarshalText. Treat the
// input and returned value as private key material.
func ParseOnionServiceKey(text []byte) (OnionServiceKey, error) {
	encoded := string(text)
	encoded = strings.TrimPrefix(encoded, "ED25519-V3:")
	b, err := decodeBase64(encoded)
	if err != nil {
		return OnionServiceKey{}, fmt.Errorf("tor-driver: invalid onion service key encoding: %w", err)
	}
	defer clear(b)
	return NewOnionServiceKey(b)
}

// MarshalText returns Tor's ED25519-V3 control-protocol representation.
// The returned bytes contain private key material.
func (k OnionServiceKey) MarshalText() ([]byte, error) {
	if !k.valid() {
		return nil, fmt.Errorf("tor-driver: invalid onion service key")
	}
	return []byte("ED25519-V3:" + base64.RawStdEncoding.EncodeToString(k.expanded[:])), nil
}

// UnmarshalText replaces k with a validated Tor expanded Ed25519 private key.
func (k *OnionServiceKey) UnmarshalText(text []byte) error {
	parsed, err := ParseOnionServiceKey(text)
	if err != nil {
		return err
	}
	clear(k.expanded[:])
	*k = parsed
	return nil
}

func (k OnionServiceKey) valid() bool {
	return k.expanded[0]&7 == 0 && k.expanded[31]&0xc0 == 0x40
}

func (k OnionServiceKey) torBlob() string {
	return base64.RawStdEncoding.EncodeToString(k.expanded[:])
}

// OnionKeyStore stores named Tor v3 service keys. Load must return
// fs.ErrNotExist when a name has no key. Store must not return until the key is
// durable. Store is a create-if-absent operation and must fail if the name was
// created after Load returned fs.ErrNotExist. Implementations must protect key
// confidentiality.
type OnionKeyStore interface {
	Load(context.Context, string) (OnionServiceKey, error)
	Store(context.Context, string, OnionServiceKey) error
}

// ClientAuthorizationPublicKey is an X25519 public key accepted by a protected
// v3 onion service.
type ClientAuthorizationPublicKey struct {
	key [clientAuthorizationKeySize]byte
}

// ClientAuthorizationPrivateKey is an X25519 private key used to access a
// protected v3 onion service.
type ClientAuthorizationPrivateKey struct {
	key [clientAuthorizationKeySize]byte
}

// ClientAuthorization contains a client-side credential and an optional Tor
// nickname. Nicknames contain 1 to 16 letters, digits, '+', '-', or '_'.
type ClientAuthorization struct {
	PrivateKey ClientAuthorizationPrivateKey
	Name       string
}

// NewClientAuthorizationPublicKey validates and copies an X25519 public key.
func NewClientAuthorizationPublicKey(key []byte) (ClientAuthorizationPublicKey, error) {
	var result ClientAuthorizationPublicKey
	if len(key) != clientAuthorizationKeySize {
		return result, fmt.Errorf("tor-driver: client authorization public key must contain 32 bytes")
	}
	curve := ecdh.X25519()
	public, err := curve.NewPublicKey(key)
	if err != nil {
		return result, fmt.Errorf("tor-driver: invalid client authorization public key: %w", err)
	}
	var validationScalar [clientAuthorizationKeySize]byte
	validationScalar[0] = 1
	private, err := curve.NewPrivateKey(validationScalar[:])
	if err != nil {
		return result, fmt.Errorf("tor-driver: create validation key: %w", err)
	}
	if _, err = private.ECDH(public); err != nil {
		return ClientAuthorizationPublicKey{}, fmt.Errorf("tor-driver: invalid client authorization public key")
	}
	copy(result.key[:], key)
	return result, nil
}

// NewClientAuthorizationPrivateKey validates and copies an X25519 private key.
func NewClientAuthorizationPrivateKey(key []byte) (ClientAuthorizationPrivateKey, error) {
	var result ClientAuthorizationPrivateKey
	if len(key) != clientAuthorizationKeySize {
		return result, fmt.Errorf("tor-driver: client authorization private key must contain 32 bytes")
	}
	if _, err := ecdh.X25519().NewPrivateKey(key); err != nil {
		return result, fmt.Errorf("tor-driver: invalid client authorization private key: %w", err)
	}
	copy(result.key[:], key)
	result.key[0] &= 248
	result.key[31] &= 127
	result.key[31] |= 64
	return result, nil
}

// ParseClientAuthorizationPublicKey parses Tor's base32 X25519 public-key
// format.
func ParseClientAuthorizationPublicKey(text []byte) (ClientAuthorizationPublicKey, error) {
	decoded, err := onionBase32.DecodeString(strings.ToUpper(strings.TrimSpace(string(text))))
	if err != nil {
		return ClientAuthorizationPublicKey{}, fmt.Errorf("tor-driver: invalid client authorization public key encoding: %w", err)
	}
	return NewClientAuthorizationPublicKey(decoded)
}

// ParseClientAuthorizationPrivateKey parses Tor's base64 X25519 private-key
// format.
func ParseClientAuthorizationPrivateKey(text []byte) (ClientAuthorizationPrivateKey, error) {
	decoded, err := decodeBase64(strings.TrimSpace(string(text)))
	if err != nil {
		return ClientAuthorizationPrivateKey{}, fmt.Errorf("tor-driver: invalid client authorization private key encoding: %w", err)
	}
	defer clear(decoded)
	return NewClientAuthorizationPrivateKey(decoded)
}

// GenerateClientAuthorization creates a client-side X25519 credential with
// caller-supplied entropy.
func GenerateClientAuthorization(random io.Reader, name string) (ClientAuthorization, error) {
	if random == nil {
		return ClientAuthorization{}, fmt.Errorf("tor-driver: entropy reader is required")
	}
	if !validClientName(name) {
		return ClientAuthorization{}, fmt.Errorf("tor-driver: invalid client authorization name")
	}
	private, err := ecdh.X25519().GenerateKey(random)
	if err != nil {
		return ClientAuthorization{}, err
	}
	key, err := NewClientAuthorizationPrivateKey(private.Bytes())
	if err != nil {
		return ClientAuthorization{}, err
	}
	return ClientAuthorization{PrivateKey: key, Name: name}, nil
}

// PublicKey returns the hosting key that corresponds to this credential.
func (a ClientAuthorization) PublicKey() (ClientAuthorizationPublicKey, error) {
	if !a.PrivateKey.valid() {
		return ClientAuthorizationPublicKey{}, fmt.Errorf("tor-driver: invalid client authorization private key")
	}
	private, err := ecdh.X25519().NewPrivateKey(a.PrivateKey.key[:])
	if err != nil {
		return ClientAuthorizationPublicKey{}, fmt.Errorf("tor-driver: invalid client authorization: %w", err)
	}
	return NewClientAuthorizationPublicKey(private.PublicKey().Bytes())
}

// MarshalText returns the base32 public-key format used by ADD_ONION.
func (k ClientAuthorizationPublicKey) MarshalText() ([]byte, error) {
	if allZero(k.key[:]) {
		return nil, fmt.Errorf("tor-driver: invalid client authorization public key")
	}
	return []byte(strings.ToLower(onionBase32.EncodeToString(k.key[:]))), nil
}

// UnmarshalText replaces k with a validated base32 X25519 public key.
func (k *ClientAuthorizationPublicKey) UnmarshalText(text []byte) error {
	parsed, err := ParseClientAuthorizationPublicKey(text)
	if err != nil {
		return err
	}
	*k = parsed
	return nil
}

// MarshalText returns the base64 private-key format used by
// ONION_CLIENT_AUTH_ADD. The returned bytes contain private key material.
func (k ClientAuthorizationPrivateKey) MarshalText() ([]byte, error) {
	if !k.valid() {
		return nil, fmt.Errorf("tor-driver: invalid client authorization private key")
	}
	if _, err := ecdh.X25519().NewPrivateKey(k.key[:]); err != nil {
		return nil, fmt.Errorf("tor-driver: invalid client authorization private key: %w", err)
	}
	return []byte(base64.StdEncoding.EncodeToString(k.key[:])), nil
}

func (k ClientAuthorizationPrivateKey) valid() bool {
	return !allZero(k.key[:]) && k.key[0]&7 == 0 && k.key[31]&0xc0 == 0x40
}

// UnmarshalText replaces k with a validated base64 X25519 private key.
func (k *ClientAuthorizationPrivateKey) UnmarshalText(text []byte) error {
	parsed, err := ParseClientAuthorizationPrivateKey(text)
	if err != nil {
		return err
	}
	clear(k.key[:])
	*k = parsed
	return nil
}

func decodeBase64(s string) ([]byte, error) {
	b, err := base64.RawStdEncoding.DecodeString(strings.TrimRight(s, "="))
	if err != nil {
		return nil, err
	}
	return b, nil
}

func validClientName(name string) bool {
	if len(name) > 16 {
		return false
	}
	for _, c := range name {
		if (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') && (c < '0' || c > '9') && c != '+' && c != '-' && c != '_' {
			return false
		}
	}
	return true
}

func validKeyName(name string) bool {
	if name == "" || len(name) > 128 {
		return false
	}
	for _, c := range name {
		if (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') && (c < '0' || c > '9') && c != '.' && c != '-' && c != '_' {
			return false
		}
	}
	return true
}

func allZero(b []byte) bool {
	var combined byte
	for _, v := range b {
		combined |= v
	}
	return combined == 0
}

func validateClientAuthorization(a ClientAuthorization) error {
	if !validClientName(a.Name) {
		return fmt.Errorf("tor-driver: invalid client authorization name")
	}
	_, err := a.PublicKey()
	return err
}

func joinDeleteError(operation, deletion error) error {
	if deletion == nil {
		return operation
	}
	return errors.Join(operation, fmt.Errorf("tor-driver: could not delete service after failure: %w", deletion))
}
