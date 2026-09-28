package storetest

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
	"github.com/yaphoa/mcpwarden/internal/audit"
	"github.com/yaphoa/mcpwarden/internal/identity"
	json "github.com/yaphoa/mcpwarden/internal/jsoncodec"
	"github.com/yaphoa/mcpwarden/internal/lease"
	"github.com/yaphoa/mcpwarden/internal/secret"
	"github.com/yaphoa/mcpwarden/internal/vault"
)

type authority struct {
	caller, browser lease.Caller
	credential      lease.Credential
}

func (a *authority) Caller(owner, id string) (lease.Caller, bool) {
	if owner != a.caller.Owner {
		return lease.Caller{}, false
	}
	if id == a.caller.AccessID {
		return a.caller, true
	}
	if id == a.browser.AccessID {
		return a.browser, true
	}
	return lease.Caller{}, false
}
func (a *authority) Credential(owner, id string) (lease.Credential, bool) {
	return a.credential, owner == a.caller.Owner && id == a.credential.ID
}

type material struct{ destroyed atomic.Int32 }

func (m *material) Destroy() { m.destroyed.Add(1) }

type activator struct{ m material }

func (a *activator) Stage(_ context.Context, _ string, _ lease.Credential, key []byte) (lease.Material, error) {
	if key[0] != 42 {
		return nil, lease.ErrKey
	}
	return &a.m, nil
}

// service is a lease service for owner "alice" with one pending (mode none)
// or approved (mode confirm) request.
type service struct {
	service         *lease.Service
	store           Store
	authority       *authority
	activator       *activator
	scope           lease.Scope
	caller, browser context.Context
	request         lease.Request
	active          lease.Lease
}

func newService(t *testing.T, store Store, budget *int64, mode string) *service {
	t.Helper()
	definition, _ := lease.DefinitionDigest([]byte(`{"name":"files.search","inputSchema":{"type":"object"}}`))
	destination, _ := lease.DefinitionDigest([]byte(`{"url":"https://example.invalid/mcp"}`))
	toolID := identity.New()
	a := &authority{caller: lease.Caller{Actor: identity.Actor{Owner: "alice", AccessID: identity.New(), Kind: "api_key", Label: "test caller", PublicID: identity.NewPublicID()}, Active: true}, browser: lease.Caller{Actor: identity.Actor{Owner: "alice", AccessID: identity.New(), Kind: "browser"}, Active: true, Interactive: true}, credential: lease.Credential{ID: identity.New(), ConnectorID: identity.New(), Epoch: "1", Revision: "1", PolicyRevision: "1", ConnectorSecurityRevision: "1", ApprovalPolicyRevision: "1", ApprovalMode: mode, Enabled: true, DestinationDigest: destination, Tools: map[string]lease.Tool{toolID: {ID: toolID, DefinitionDigest: definition, Allowed: true, Visible: true}}}}
	scope := lease.Scope{Schema: lease.ScopeSchema, OwnerID: "alice", RequesterAccessID: a.caller.AccessID, ConnectorID: a.credential.ConnectorID, CredentialID: a.credential.ID, CredentialEpoch: "1", PolicyRevision: "1", ConnectorSecurityRevision: "1", DestinationDigest: destination, DurationSeconds: 900, Purpose: "tool_use", Tools: []lease.ToolScope{{ToolID: toolID, DefinitionDigest: definition, Constraints: []lease.Constraint{}}}, MaxCalls: budget}
	act := &activator{}
	opts := lease.DefaultOptions()
	opts.MaxConcurrent = 128
	s, err := lease.New(t.Context(), store, a, act, opts)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	f := &service{service: s, store: store, authority: a, activator: act, scope: scope, caller: identity.WithActor(t.Context(), a.caller.Actor), browser: identity.WithActor(t.Context(), a.browser.Actor)}
	raw, _ := json.Marshal(scope)
	f.request, err = s.Request(f.caller, raw)
	if err != nil {
		t.Fatal(err)
	}
	if mode == "confirm" {
		f.request, err = s.Confirm(f.browser, f.request.ID, f.request.RequestDigest)
		if err != nil {
			t.Fatal(err)
		}
	}
	return f
}

func activationInput(r lease.Request) lease.ActivationInput {
	key := make([]byte, 32)
	key[0] = 42
	return lease.ActivationInput{RequestID: r.ID, RequestDigest: r.RequestDigest, OperationID: identity.New(), Key: key}
}

func (f *service) activate(t *testing.T) {
	t.Helper()
	var err error
	f.active, err = f.service.Activate(f.browser, activationInput(f.request))
	if err != nil {
		t.Fatal(err)
	}
}

func (f *service) admit() (*lease.Admission, error) {
	r := audit.NewInvocation(f.caller, "alice")
	r.ToolID = f.scope.Tools[0].ToolID
	r.Tool = "files.search"
	r.UpstreamID = f.scope.ConnectorID
	r.ArgsSHA256 = audit.HashArgs(json.RawMessage(`{}`))
	return f.service.Admit(f.caller, f.scope.CredentialID, r.ToolID, f.scope.Tools[0].DefinitionDigest, []byte(`{}`), r)
}

// completion is the completion record of an admission.
func completion(a audit.Record) audit.Record {
	c := a
	c.EventID = identity.New()
	c.EventType = audit.DispatchCompleted
	c.Status = "ok"
	c.CompletedAt = time.Now().UTC()
	c.OccurredAt = c.CompletedAt
	return c
}

func started(t *testing.T, db Database) Store {
	t.Helper()
	s := db.Open(t)
	if err := s.Start(t.Context(), identity.New()); err != nil {
		t.Fatal(err)
	}
	return s
}

func randomEncoded(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

// vaultRootFixture holds opaque wrappers: the tests exercise storage without
// giving the server a vault root.
func vaultRootFixture(owner string) vault.Root {
	r := vault.Root{OwnerID: owner, RootID: identity.New(), RootVersion: "1", WrapperRevision: "1"}
	for _, method := range []string{"passphrase", "recovery"} {
		var k any = secret.RecoveryKDF{Suite: "HKDF-SHA256", OutputBytes: 32, HKDFInfo: secret.RecoveryInfo}
		if method == "passphrase" {
			k = secret.PassphraseKDF{Suite: "ARGON2ID-HKDF-SHA256", ArgonVersion: 19, MemoryKiB: 65536, Iterations: 3, Parallelism: 4, Salt: randomEncoded(16), OutputBytes: 32, HKDFInfo: secret.PassphraseInfo}
		}
		kd, _ := json.Marshal(k)
		w := secret.RootWrapper{Format: "mcpwarden.root-wrap.v1", Algorithm: secret.Algorithm, Purpose: "vault-root", RootContext: secret.RootContext{OwnerID: owner, RootID: r.RootID, RootVersion: "1", WrapperID: identity.New(), Method: method}, KDF: kd, Nonce: randomEncoded(12), Ciphertext: randomEncoded(48)}
		raw, _ := json.Marshal(w)
		if method == "passphrase" {
			r.Passphrase = raw
		} else {
			r.Recovery = raw
		}
	}
	return r
}

func credentialFixture(t *testing.T, root vault.Root) vault.Record {
	t.Helper()
	r := vault.Record{CredentialContext: secret.CredentialContext{OwnerID: root.OwnerID, RootID: root.RootID, RootVersion: root.RootVersion, ConnectorID: identity.New(), CredentialID: identity.New(), Epoch: "1"}, Revision: "1", Destination: secret.Destination{Schema: "mcpwarden.destination.v1", Endpoint: "https://example.com/mcp", HeaderNames: []string{"authorization"}, Network: "public"}}
	wrapFixture(&r)
	return encryptFixture(t, r)
}

func wrapFixture(r *vault.Record) {
	r.WrappedKey, _ = json.Marshal(secret.CredentialWrapper{Format: "mcpwarden.credential-wrap.v1", Algorithm: secret.Algorithm, Purpose: "credential-key", CredentialContext: r.CredentialContext, Nonce: randomEncoded(12), Ciphertext: randomEncoded(48)})
}

// encryptFixture seals a synthetic credential under a test CEK.
func encryptFixture(t *testing.T, r vault.Record) vault.Record {
	t.Helper()
	digest, _ := r.Destination.Digest()
	header := secret.Header{Format: secret.Format, Algorithm: secret.Algorithm, Purpose: "upstream-credential", OwnerID: r.OwnerID, ConnectorID: r.ConnectorID, CredentialID: r.CredentialID, Epoch: r.Epoch, Revision: r.Revision, DestinationDigest: digest}
	raw, _ := json.Marshal(header)
	aad, err := jsoncanonicalizer.Transform(raw)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := aes.NewCipher(bytes.Repeat([]byte{9}, 32))
	aead, _ := cipher.NewGCM(block)
	nonce := make([]byte, 12)
	_, _ = rand.Read(nonce)
	plain := []byte(`{"kind":"header_bundle","headers":[{"name":"Authorization","value":"Bearer SYNTHETIC_LEASE_TOKEN"}]}`)
	envelope := secret.Envelope{Header: header, Nonce: base64.RawURLEncoding.EncodeToString(nonce), Ciphertext: base64.RawURLEncoding.EncodeToString(aead.Seal(nil, nonce, plain, aad))}
	if r.Envelope, err = json.Marshal(envelope); err != nil {
		t.Fatal(err)
	}
	return r
}

func withVault(t *testing.T, s Store, owner string, fn func(vault.Tx) error) error {
	t.Helper()
	return s.WithOwner(t.Context(), owner, func(tx lease.Tx) error { return fn(tx.(vault.Tx)) })
}

// vaultWithCredential stores a root and one credential for alice.
func vaultWithCredential(t *testing.T, s Store) (vault.Root, vault.Record) {
	t.Helper()
	root := vaultRootFixture("alice")
	r := credentialFixture(t, root)
	if err := withVault(t, s, "alice", func(tx vault.Tx) error {
		if err := tx.PutVaultRoot(root, ""); err != nil {
			return err
		}
		return tx.PutCredentialRecord(r, nil)
	}); err != nil {
		t.Fatal(err)
	}
	return root, r
}
