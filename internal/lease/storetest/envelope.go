package storetest

import (
	"encoding/base64"
	"strconv"
	"testing"

	json "github.com/yaphoa/mcpwarden/internal/jsoncodec"
)

// testEnvelopeEpochTyping writes a credential version whose envelope spells
// its epoch in each JSON form. Both stores accept the integer and its decimal
// string and refuse every other form, except 1e0: jsonb keeps it as the
// number 1, so PostgreSQL accepts it, while SQLite reads a real and refuses
// it. Browsers and the gateway write the epoch as a string.
func testEnvelopeEpochTyping(t *testing.T, db Database) {
	s := started(t, db)
	_, r := vaultWithCredential(t, s)
	head := 1
	for _, c := range []struct {
		epoch    string // raw JSON; empty leaves the field out
		accepted bool
	}{
		{`1`, true}, {`"1"`, true},
		{`"01"`, false}, {``, false}, {`null`, false}, {`true`, false}, {`1.0`, false},
		{`10e-1`, false}, {`" 1"`, false}, {`"1 "`, false}, {`"+1"`, false}, {`[1]`, false},
		{`1e0`, db.Driver() == "postgres"},
	} {
		next := r
		next.Revision = strconv.Itoa(head + 1)
		next = encryptFixture(t, next)
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(next.Envelope, &fields); err != nil {
			t.Fatal(err)
		}
		delete(fields, "epoch")
		if c.epoch != "" {
			fields["epoch"] = json.RawMessage(c.epoch)
		}
		envelope, _ := json.Marshal(fields)
		var nonce string
		if err := json.Unmarshal(fields["nonce"], &nonce); err != nil {
			t.Fatal(err)
		}
		var stored any = nonce
		if db.Driver() == "postgres" {
			stored, _ = base64.RawURLEncoding.DecodeString(nonce)
		}
		err := db.Exec(t, pick(db,
			"INSERT INTO credential_versions(owner_id,credential_id,epoch,revision,nonce,envelope) VALUES($1,$2,1,$3,$4,$5::jsonb)",
			"INSERT INTO credential_versions(owner_id,credential_id,epoch,revision,nonce,envelope,created_at) VALUES($1,$2,1,$3,$4,$5,0)"),
			r.OwnerID, r.CredentialID, head+1, stored, string(envelope))
		switch {
		case c.accepted && err != nil:
			t.Errorf("epoch %s refused: %v", c.epoch, err)
		case c.accepted:
			head++
		case !db.Constraint(err):
			t.Errorf("epoch %s not refused by a constraint: %v", c.epoch, err)
		}
	}
	stillOpen(t, s)
}
