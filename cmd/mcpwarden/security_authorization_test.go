package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/yaphoa/mcpwarden/internal/catalog"
	"github.com/yaphoa/mcpwarden/internal/identity"
	json "github.com/yaphoa/mcpwarden/internal/jsoncodec"
	"github.com/yaphoa/mcpwarden/internal/secret"
	"github.com/yaphoa/mcpwarden/internal/vault"
)

func (f *ownerFixture) pausedMutation(method, path, body string, before func()) *httptest.ResponseRecorder {
	f.t.Helper()
	r := httptest.NewRequest(method, panelOrigin+path, &bodyReadHook{Reader: strings.NewReader(body), before: before})
	r.ContentLength = int64(len(body))
	r.Header.Set("Origin", panelOrigin)
	r.Header.Set("Sec-Fetch-Site", "same-origin")
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("X-CSRF-Token", f.csrfToken())
	r.AddCookie(&http.Cookie{Name: sessionCookie, Value: f.cookies["alice"]})
	w := httptest.NewRecorder()
	f.mux.ServeHTTP(w, r)
	if _, active := f.accounts.session(r); active {
		f.t.Fatal("test did not revoke the submitting browser session")
	}
	return w
}

func TestOwnerMutationsRejectRevokedSession(t *testing.T) {
	for _, mutation := range []string{"setup", "wrappers", "create", "rotate", "delete", "policy"} {
		t.Run(mutation, func(t *testing.T) {
			f := newOwnerFixture(t)
			var root vault.Root
			var record vault.Record
			if mutation != "setup" {
				root, record = f.provision("none")
			}
			method, path, body := "PUT", "", ""
			switch mutation {
			case "setup":
				method, path = "POST", "/api/vault/setup"
				body = encode(rootInput{CurrentPassword: testPassword, Root: rootFixture(f.owners["alice"])})
			case "wrappers":
				path = "/api/vault/wrappers"
				rewrapped := rootFixture(f.owners["alice"])
				rewrapped.RootID, rewrapped.WrapperRevision = root.RootID, "2"
				for _, raw := range []*json.RawMessage{&rewrapped.Passphrase, &rewrapped.Recovery} {
					var wrapper secret.RootWrapper
					if err := json.Unmarshal(*raw, &wrapper); err != nil {
						t.Fatal(err)
					}
					wrapper.RootID = root.RootID
					*raw, _ = json.Marshal(wrapper)
				}
				body = encode(rootInput{CurrentPassword: testPassword, ExpectedWrapperRevision: "1", Root: rewrapped})
			case "create":
				next := f.credentialRecord(root, identity.New(), "1", "1", randBytes(32))
				path = "/api/vault/credentials/" + next.CredentialID
				body = encode(map[string]any{"record": next})
			case "rotate":
				next := f.credentialRecord(root, record.CredentialID, "2", "1", randBytes(32))
				path = "/api/vault/credentials/" + record.CredentialID
				body = encode(map[string]any{"expected": pointerInput{Epoch: "1", Revision: "1"}, "record": next})
			case "delete":
				method, path = "DELETE", "/api/vault/credentials/"+record.CredentialID
				body = encode(map[string]any{"expected": pointerInput{Epoch: "1", Revision: "1"}})
			case "policy":
				path = "/api/security/approval-policy"
				body = encode(map[string]string{"mode": "confirm", "expected_revision": "2", "current_password": testPassword})
			}
			var before, after int
			count := func(out *int) {
				t.Helper()
				if err := f.db.Admin.QueryRow(t.Context(), "SELECT count(*) FROM mcpwarden_security.security_events WHERE owner_id=$1", f.owners["alice"]).Scan(out); err != nil {
					t.Fatal(err)
				}
			}
			count(&before)
			w := f.pausedMutation(method, path, body, func() {
				f.expect(req{method: "POST", path: "/api/auth/logout", user: "alice", body: "{}", skipCSRF: true}, 204, nil)
			})
			count(&after)
			if w.Code != http.StatusForbidden || before != after {
				t.Fatalf("revoked browser mutation: status=%d, committed events before=%d after=%d", w.Code, before, after)
			}
			if mutation == "rotate" || mutation == "delete" {
				head, ok := f.api.index.Credential(f.owners["alice"], record.CredentialID)
				if !ok || head.Epoch != "1" || head.Deleted {
					t.Fatal("revoked browser changed credential authority")
				}
			}
		})
	}
}

func TestOwnerCredentialWriteRejectsReplacedSession(t *testing.T) {
	for _, replacement := range []string{"access revocation", "new login", "password change"} {
		t.Run(replacement, func(t *testing.T) {
			f := newOwnerFixture(t)
			root, record := f.provision("none")
			next := f.credentialRecord(root, record.CredentialID, "2", "1", randBytes(32))
			body := encode(map[string]any{"expected": pointerInput{Epoch: "1", Revision: "1"}, "record": next})
			old, ok := f.store.AuthenticateAccess(tokenHash(f.cookies["alice"]), "browser")
			if !ok {
				t.Fatal("missing session")
			}
			w := f.pausedMutation("PUT", "/api/vault/credentials/"+record.CredentialID, body, func() {
				switch replacement {
				case "access revocation":
					f.expect(req{method: "DELETE", path: "/api/access/" + old.ID, user: "alice", skipCSRF: true}, 204, nil)
				case "new login":
					f.expect(req{method: "POST", path: "/api/auth/login", user: "alice", skipCSRF: true, body: encode(map[string]string{"username": "alice", "password": testPassword})}, 200, nil)
				case "password change":
					f.cookies["alice"] = f.session("alice")
					f.expect(req{method: "POST", path: "/api/auth/password", user: "alice", skipCSRF: true, body: encode(map[string]string{"current_password": testPassword, "new_password": "new synthetic owner password"})}, 204, nil)
				}
			})
			head, ok := f.api.index.Credential(f.owners["alice"], record.CredentialID)
			if w.Code != http.StatusForbidden || !ok || head.Epoch != "1" {
				t.Fatalf("replaced session wrote credential: status=%d, epoch=%s", w.Code, head.Epoch)
			}
		})
	}
}

func TestOwnerMutationRechecksSessionAfterDatabaseWait(t *testing.T) {
	f := newOwnerFixture(t)
	root, record := f.provision("none")
	next := f.credentialRecord(root, record.CredentialID, "2", "1", randBytes(32))
	body := encode(map[string]any{"expected": pointerInput{Epoch: "1", Revision: "1"}, "record": next})
	// Hold the durable owner lock. HTTP authentication occurs before this wait;
	// authorization must be repeated with a current clock after it is released.
	tx, err := f.db.Admin.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(context.Background())
	if _, err := tx.Exec(t.Context(), "SELECT owner_id FROM mcpwarden_security.owners WHERE owner_id=$1 FOR UPDATE", f.owners["alice"]); err != nil {
		t.Fatal(err)
	}
	expires := time.Now().Add(750 * time.Millisecond)
	token := randomToken()
	if err := f.store.AddAccess(catalog.AccessRecord{ID: identity.New(), Owner: f.owners["alice"], Name: "short lived browser", Kind: "browser", Role: "admin", SecretHash: tokenHash(token), ExpiresAt: expires}); err != nil {
		t.Fatal(err)
	}
	f.cookies["alice"] = token
	response := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		response <- f.do(req{method: "PUT", path: "/api/vault/credentials/" + record.CredentialID, user: "alice", body: body})
	}()
	deadline := time.Now().Add(1500 * time.Millisecond)
	for {
		var waiting bool
		if _, err := tx.Exec(t.Context(), "SELECT pg_stat_clear_snapshot()"); err != nil {
			t.Fatal(err)
		}
		if err := tx.QueryRow(t.Context(), "SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND application_name='mcpwarden-security' AND wait_event_type='Lock')").Scan(&waiting); err != nil {
			t.Fatal(err)
		}
		if waiting {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("mutation never waited for the owner lock")
		}
		time.Sleep(5 * time.Millisecond)
	}
	if delay := time.Until(expires.Add(10 * time.Millisecond)); delay > 0 {
		time.Sleep(delay)
	}
	if err := tx.Commit(t.Context()); err != nil {
		t.Fatal(err)
	}
	select {
	case w := <-response:
		head, ok := f.api.index.Credential(f.owners["alice"], record.CredentialID)
		if w.Code != http.StatusForbidden || !ok || head.Epoch != "1" {
			t.Fatalf("expired queued mutation: status=%d, epoch=%s", w.Code, head.Epoch)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("mutation did not finish after the owner lock was released")
	}
}

func TestOwnerPasswordProofDoesNotSurvivePasswordChange(t *testing.T) {
	f := newOwnerFixture(t)
	proof, status := f.accounts.verifyCurrentPassword(f.owners["alice"], testPassword)
	if status != 0 {
		t.Fatal("password verification failed")
	}
	defer clear(proof.hash)
	if !f.accounts.passwordUnchanged(proof) {
		t.Fatal("fresh proof unavailable")
	}
	f.expect(req{method: "POST", path: "/api/auth/password", user: "alice", skipCSRF: true, body: encode(map[string]string{"current_password": testPassword, "new_password": "new synthetic owner password"})}, 204, nil)
	if f.accounts.passwordUnchanged(proof) {
		t.Fatal("stale password proof survived a password change")
	}
}
