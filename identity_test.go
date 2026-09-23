package tordriver

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func TestOnionServiceKeyExpansionAndText(t *testing.T) {
	seed, err := hex.DecodeString("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
	if err != nil {
		t.Fatal(err)
	}
	want, err := hex.DecodeString("307c83864f2833cb427a2ef1c00a013cfdff2768d980c0a3a520f006904de94f9b4f0afe280b746a778684e75442502057b7473a03f08f96f5a38e9287e01f8f")
	if err != nil {
		t.Fatal(err)
	}
	key, err := OnionServiceKeyFromEd25519Seed(seed)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(key.expanded[:], want) {
		t.Fatalf("expanded key = %x, want %x", key.expanded, want)
	}
	text, err := key.MarshalText()
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseOnionServiceKey(text)
	if err != nil {
		t.Fatal(err)
	}
	if parsed != key {
		t.Fatal("onion service key did not survive text round trip")
	}
	if _, err = NewOnionServiceKey(seed); err == nil {
		t.Fatal("generic Ed25519 seed was accepted as an expanded key")
	}
}

func TestClientAuthorizationKeyRoundTrip(t *testing.T) {
	authorization, err := GenerateClientAuthorization(bytes.NewReader(bytes.Repeat([]byte{1}, 64)), "client_1")
	if err != nil {
		t.Fatal(err)
	}
	public, err := authorization.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	publicText, err := public.MarshalText()
	if err != nil {
		t.Fatal(err)
	}
	parsedPublic, err := ParseClientAuthorizationPublicKey(publicText)
	if err != nil {
		t.Fatal(err)
	}
	if parsedPublic != public || len(publicText) != 52 {
		t.Fatal("public authorization key did not survive base32 round trip")
	}
	privateText, err := authorization.PrivateKey.MarshalText()
	if err != nil {
		t.Fatal(err)
	}
	parsedPrivate, err := ParseClientAuthorizationPrivateKey(privateText)
	if err != nil {
		t.Fatal(err)
	}
	if parsedPrivate != authorization.PrivateKey || len(privateText) != 44 {
		t.Fatal("private authorization key did not survive base64 round trip")
	}
	if _, err = GenerateClientAuthorization(bytes.NewReader(make([]byte, 64)), "bad name"); err == nil {
		t.Fatal("unsafe authorization name accepted")
	}
	lowOrder := make([]byte, 32)
	lowOrder[0] = 1
	if _, err = NewClientAuthorizationPublicKey(lowOrder); err == nil {
		t.Fatal("low-order client authorization public key accepted")
	}
	if _, err = (ClientAuthorizationPrivateKey{}).MarshalText(); err == nil {
		t.Fatal("zero-value client authorization private key encoded")
	}
}
