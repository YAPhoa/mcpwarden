package storetest

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"
	"testing"

	json "github.com/yaphoa/mcpwarden/internal/jsoncodec"
)

// spellings are the JSON forms of the number n that an identity field may
// take, and whether both stores accept them. They accept the integer and its
// decimal string and refuse every other form, except an exponent: jsonb keeps
// 1e0 as the number 1, so PostgreSQL accepts it, while SQLite reads a real
// and refuses it. The gateway and browser write these fields as strings.
func spellings(db Database, n int) []struct {
	json     string // empty leaves the field out
	accepted bool
} {
	return []struct {
		json     string
		accepted bool
	}{
		{fmt.Sprint(n), true}, {fmt.Sprintf(`"%d"`, n), true},
		{fmt.Sprintf(`"0%d"`, n), false}, {``, false}, {`null`, false}, {`true`, false}, {fmt.Sprintf(`%d.0`, n), false},
		{fmt.Sprintf(`%d0e-1`, n), false}, {fmt.Sprintf(`" %d"`, n), false}, {fmt.Sprintf(`"%d "`, n), false},
		{fmt.Sprintf(`"+%d"`, n), false}, {fmt.Sprintf(`[%d]`, n), false},
		{fmt.Sprintf(`%de0`, n), db.Driver() == "postgres"},
	}
}

// patch returns doc with field replaced by the raw JSON value, or removed.
func patch(t *testing.T, doc []byte, field, value string) string {
	t.Helper()
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(doc, &fields); err != nil {
		t.Fatal(err)
	}
	delete(fields, field)
	if value != "" {
		fields[field] = json.RawMessage(value)
	}
	out, _ := json.Marshal(fields)
	return string(out)
}

// testJSONIdentityTyping writes each of the six integer columns that are
// also stored inside JSON (the envelope's epoch and revision, the wrapped
// key's epoch and root version, and the root version of both root
// wrappers) in every spelling, and checks both stores agree.
func testJSONIdentityTyping(t *testing.T, db Database) {
	s := started(t, db)
	_, r := vaultWithCredential(t, s)
	accepted := func(t *testing.T, want bool, field, value string, err error) {
		t.Helper()
		switch {
		case want && err != nil:
			t.Errorf("%s %s refused: %v", field, value, err)
		case !want && err == nil:
			t.Errorf("%s %s accepted", field, value)
		case !want && !db.Constraint(err):
			t.Errorf("%s %s not refused by a constraint: %v", field, value, err)
		}
	}

	head := 1
	for _, field := range []string{"epoch", "revision"} {
		t.Run("envelope "+field, func(t *testing.T) {
			for i := range spellings(db, 1) {
				// The next revision moves after each accepted spelling.
				c := spellings(db, map[string]int{"epoch": 1, "revision": head + 1}[field])[i]
				next := r
				next.Revision = strconv.Itoa(head + 1)
				next = encryptFixture(t, next)
				var e struct {
					Nonce string `json:"nonce"`
				}
				_ = json.Unmarshal(next.Envelope, &e)
				var nonce any = e.Nonce
				if db.Driver() == "postgres" {
					nonce, _ = base64.RawURLEncoding.DecodeString(e.Nonce)
				}
				err := db.Exec(t, pick(db,
					"INSERT INTO credential_versions(owner_id,credential_id,epoch,revision,nonce,envelope) VALUES($1,$2,1,$3,$4,$5::jsonb)",
					"INSERT INTO credential_versions(owner_id,credential_id,epoch,revision,nonce,envelope,created_at) VALUES($1,$2,1,$3,$4,$5,0)"),
					r.OwnerID, r.CredentialID, head+1, nonce, patch(t, next.Envelope, field, c.json))
				accepted(t, c.accepted, "envelope "+field, c.json, err)
				if c.accepted && err == nil {
					head++
				}
			}
		})
	}

	wrappedKey := []byte(db.Text(t, "SELECT wrapped_key"+pick(db, "::text", "")+" FROM credential_epochs WHERE epoch=1"))
	epoch := 1
	for _, field := range []string{"epoch", "root_version"} {
		t.Run("wrapped key "+field, func(t *testing.T) {
			for i := range spellings(db, 1) {
				c := spellings(db, map[string]int{"epoch": epoch + 1, "root_version": 1}[field])[i]
				// Each epoch needs its own wrapping nonce.
				raw := make([]byte, 12)
				_, _ = rand.Read(raw)
				text := base64.RawURLEncoding.EncodeToString(raw)
				var stored any = text
				if db.Driver() == "postgres" {
					stored = raw
				}
				doc := patch(t, []byte(patch(t, wrappedKey, "nonce", strconv.Quote(text))), "epoch", strconv.Quote(strconv.Itoa(epoch+1)))
				err := db.Exec(t, "INSERT INTO credential_epochs (owner_id,credential_id,connector_id,epoch,root_id,root_version,destination_digest,destination,wrapped_key,wrap_nonce,write_count) "+
					"SELECT owner_id,credential_id,connector_id,$1,root_id,root_version,destination_digest,destination,$2"+pick(db, "::jsonb", "")+",$3,0 FROM credential_epochs WHERE epoch=1",
					epoch+1, patch(t, []byte(doc), field, c.json), stored)
				accepted(t, c.accepted, "wrapped key "+field, c.json, err)
				if c.accepted && err == nil {
					epoch++
				}
			}
		})
	}

	// At epoch 1, SQLite compares `true` as the text '1', so only the type
	// check refuses it. Epoch 1 exists, so a spelling the CHECK accepts
	// reaches the primary key instead.
	t.Run("wrapped key epoch 1", func(t *testing.T) {
		for _, c := range spellings(db, 1) {
			doc := patch(t, wrappedKey, "epoch", c.json)
			err := db.Exec(t, "INSERT INTO credential_epochs (owner_id,credential_id,connector_id,epoch,root_id,root_version,destination_digest,destination,wrapped_key,wrap_nonce,write_count) "+
				"SELECT owner_id,credential_id,connector_id,1,root_id,root_version,destination_digest,destination,$1"+pick(db, "::jsonb", "")+",wrap_nonce,0 FROM credential_epochs WHERE epoch=1", doc)
			want := pick(db, "credential_epochs_check ", "CHECK constraint failed")
			if c.accepted {
				want = pick(db, "credential_epochs_pkey", "UNIQUE constraint failed: credential_epochs")
			}
			if err == nil || !strings.Contains(db.Rule(err), want) {
				t.Errorf("wrapped key epoch %s: refused by %v, want %q", c.json, err, want)
			}
		}
	})

	wrappers := map[string][]byte{}
	for _, column := range []string{"passphrase", "recovery"} {
		wrappers[column] = []byte(db.Text(t, "SELECT "+column+pick(db, "::text", "")+" FROM vault_wrapper_sets WHERE wrapper_revision=1"))
	}
	revision := 1
	for _, column := range []string{"passphrase", "recovery"} {
		t.Run(column+" root_version", func(t *testing.T) {
			for _, c := range spellings(db, 1) {
				values := map[string]string{"passphrase": string(wrappers["passphrase"]), "recovery": string(wrappers["recovery"])}
				values[column] = patch(t, wrappers[column], "root_version", c.json)
				jsonb := pick(db, "::jsonb", "")
				err := db.Exec(t, "INSERT INTO vault_wrapper_sets (owner_id,root_id,root_version,wrapper_revision,passphrase,recovery"+pick(db, "", ",created_at")+") "+
					"SELECT owner_id,root_id,root_version,$1,$2"+jsonb+",$3"+jsonb+pick(db, "", ",created_at")+" FROM vault_wrapper_sets WHERE wrapper_revision=1",
					revision+1, values["passphrase"], values["recovery"])
				accepted(t, c.accepted, column+" root_version", c.json, err)
				if c.accepted && err == nil {
					revision++
				}
			}
		})
	}
	stillOpen(t, s)
}
