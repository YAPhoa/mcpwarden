package storetest

import (
	"bytes"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/yaphoa/mcpwarden/internal/catalog/catalogdb"
	"github.com/yaphoa/mcpwarden/internal/identity"
	json "github.com/yaphoa/mcpwarden/internal/jsoncodec"
	"github.com/yaphoa/mcpwarden/internal/vault"
)

// rule fails unless sql is refused by the rule want names: a substring of
// db.Rule, such as a constraint name, a guard's message or a SQLSTATE.
func rule(t *testing.T, db Database, want, sql string, args ...any) {
	t.Helper()
	err := db.Exec(t, sql, args...)
	if err == nil {
		t.Fatalf("accepted: %s", sql)
	}
	if got := db.Rule(err); !strings.Contains(got, want) {
		t.Fatalf("%s: refused by %q, want %q", sql, got, want)
	}
}

// insertSQL builds an insert of column/value pairs; a repeated column
// replaces the earlier value.
func insertSQL(table string, pairs ...any) (string, []any) {
	var columns []string
	var args []any
	for i := 0; i < len(pairs); i += 2 {
		column := pairs[i].(string)
		if j := slices.Index(columns, column); j >= 0 {
			args[j] = pairs[i+1]
			continue
		}
		columns, args = append(columns, column), append(args, pairs[i+1])
	}
	marks := make([]string, len(columns))
	for i := range marks {
		marks[i] = "$" + strconv.Itoa(i+1)
	}
	return "INSERT INTO " + table + " (" + strings.Join(columns, ",") + ") VALUES (" + strings.Join(marks, ",") + ")", args
}

// testSchemaRules sets up valid rows by raw SQL, then runs one violating
// statement per schema rule and checks which rule refused it. Deletes aim at
// rows nothing references where the schema allows one, so a foreign key
// cannot be what refuses them.
func testSchemaRules(t *testing.T, db Database) {
	s := started(t, db)
	root, cred := vaultWithCredential(t, s)
	// After a rewrap and an update, wrapper set 1 and credential version 1
	// are rows nothing references.
	root.WrapperRevision = "2"
	if err := withVault(t, s, "alice", func(tx vault.Tx) error { return tx.PutVaultRoot(root, "1") }); err != nil {
		t.Fatal(err)
	}
	next := cred
	next.Revision = "2"
	next = encryptFixture(t, next)
	if err := withVault(t, s, "alice", func(tx vault.Tx) error {
		return tx.PutCredentialRecord(next, &vault.Pointer{Epoch: "1", Revision: "1"})
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.InsertHistory(t.Context(), catalogdb.HistoryRow{OwnerID: "alice", EventID: "h1", SchemaVersion: 2, EventType: "tool.dispatch.admitted", InvocationID: "inv-1",
		ToolID: "tool-1", Tool: "x", Upstream: "u", Status: "unknown", TSNano: 1, HistoryNano: 1, Record: `{"schema_version":2}`, Source: "live"}); err != nil {
		t.Fatal(err)
	}

	base := time.Date(2026, 9, 28, 12, 0, 0, 0, time.UTC)
	at := func(d time.Duration) any {
		if db.Driver() == "postgres" {
			return base.Add(d)
		}
		return base.Add(d).UnixMicro()
	}
	insert := func(table string, pairs ...any) {
		t.Helper()
		sql, args := insertSQL(table, pairs...)
		if err := db.Exec(t, sql, args...); err != nil {
			t.Fatalf("%s: %v", sql, err)
		}
	}
	boot := identity.New()
	binding := func(id, mode, drop string) string {
		b := map[string]any{"id": id, "boot_id": boot, "scope": map[string]any{"owner_id": "alice"}}
		if mode != "" {
			b["mode"] = mode
		}
		switch drop {
		case "scope.owner_id":
			b["scope"] = map[string]any{}
		case "":
		default:
			delete(b, drop)
		}
		raw, _ := json.Marshal(b)
		return string(raw)
	}
	request := func(id, state string, pairs ...any) []any {
		return append([]any{"owner_id", "alice", "request_id", id, "boot_id", boot, "created_at", at(0), "expires_at", at(4 * time.Minute),
			"binding", binding(id, "confirm", ""), "state", state}, pairs...)
	}
	decided := func(source string) []any {
		return []any{"decided_at", at(time.Minute), "activation_deadline", at(3 * time.Minute), "approver_id", identity.New(), "authorization_source", source}
	}
	lease := func(id, request string, maxCalls any, pairs ...any) []any {
		return append([]any{"owner_id", "alice", "lease_id", id, "request_id", request, "caller_id", identity.New(), "credential_id", identity.New(),
			"epoch", 1, "boot_id", boot, "scope_digest", strings.Repeat("a", 43), "state", "active", "activated_at", at(2 * time.Minute),
			"expires_at", at(30 * time.Minute), "max_calls", maxCalls, "activation_actor_id", identity.New(), "operation_id", identity.New()}, pairs...)
	}

	insert("owners", "owner_id", "carol") // nothing else
	insert("owners", "owner_id", "dave")
	reqFree, reqSpare, reqLeased, reqCalls, reqApproved, reqDenied, reqDecided := identity.New(), identity.New(), identity.New(), identity.New(), identity.New(), identity.New(), identity.New()
	leaseFree, leaseCalls, leaseDecided := identity.New(), identity.New(), identity.New()
	insert("requests", request(reqFree, "pending")...)
	insert("requests", request(reqSpare, "pending")...)
	insert("requests", request(reqLeased, "pending")...)
	insert("leases", lease(leaseFree, reqLeased, 3)...)
	insert("requests", request(reqCalls, "pending")...)
	insert("leases", lease(leaseCalls, reqCalls, nil)...)
	insert("invocation_events", "owner_id", "alice", "event_id", identity.New(), "invocation_id", "0f000000-0000-4000-8000-000000000001", "event_type", "tool.dispatch.admitted",
		"occurred_at", at(3*time.Minute), "request_id", reqCalls, "lease_id", leaseCalls, "metadata", "{}")
	insert("requests", append(request(reqApproved, "approved"), decided("owner_confirmation")...)...)
	insert("requests", request(reqDenied, "denied")...)
	insert("requests", request(reqDecided, "pending")...)
	insert("leases", lease(leaseDecided, reqDecided, nil)...)
	if err := db.Exec(t, "UPDATE requests SET state='denied',decided_at=$1,lease_id=$2 WHERE request_id=$3", at(time.Minute), leaseDecided, reqDecided); err != nil {
		t.Fatal(err)
	}
	insert("security_events", "owner_id", "alice", "event_id", identity.New(), "event_type", "request.created", "occurred_at", at(0), "boot_id", boot, "metadata", "{}")
	insert("approval_policies", "owner_id", "alice", "mode", "confirm", "revision", 2, "changed_at", at(0), "changed_by", identity.New())
	insert("catalog_accounts", "owner_id", "alice", "username", "alice", "sealed", sealed("account"))
	insert("catalog_access", "access_id", "access-1", "owner_id", "alice", "secret_digest", bytes.Repeat([]byte{1}, 32), "kind", "api_key", "role", "admin", "sealed", sealed("a"))
	insert("catalog_connectors", "connector_id", identity.New(), "owner_id", "alice", "name", "files", "auth_type", "none", "sealed", sealed("c"))

	check := func(postgres, sqlite string) string { return pick(db, postgres, "CHECK constraint failed: "+sqlite) }
	historyColumns := "owner_id,event_id,schema_version,event_type,invocation_id,tool_id,tool,upstream,status,actor_access_id,ts_ns,history_ns,timed,failed,forwarded," +
		"handler_us,gateway_us,upstream_us,handler_bucket,gateway_bucket,upstream_bucket,record" + pick(db, ",source", "")
	historyRest := "tool_id,tool,upstream,status,actor_access_id,ts_ns,history_ns,timed,failed,forwarded," +
		"handler_us,gateway_us,upstream_us,handler_bucket,gateway_bucket,upstream_bucket,record" + pick(db, ",source", "")
	copyHistory := func(values string) string {
		return "INSERT INTO history_events (" + historyColumns + ") SELECT " + values + "," + historyRest + " FROM history_events WHERE event_id='h1'"
	}

	for _, c := range []struct {
		name string
		fn   func(t *testing.T)
	}{
		// Guards on requests. The terminal guard's nullable columns change
		// both from and to NULL, so a plain comparison would miss them.
		{"request terminal/decided_at from NULL", func(t *testing.T) {
			rule(t, db, "terminal request", "UPDATE requests SET decided_at=$1 WHERE request_id=$2", at(time.Minute), reqDenied)
		}},
		{"request terminal/decided_at to NULL", func(t *testing.T) {
			rule(t, db, "terminal request", "UPDATE requests SET decided_at=NULL WHERE request_id=$1", reqDecided)
		}},
		{"request terminal/lease_id from NULL", func(t *testing.T) {
			rule(t, db, "terminal request", "UPDATE requests SET lease_id=$1 WHERE request_id=$2", leaseDecided, reqDenied)
		}},
		{"request terminal/lease_id to NULL", func(t *testing.T) {
			rule(t, db, "terminal request", "UPDATE requests SET lease_id=NULL WHERE request_id=$1", reqDecided)
		}},
		{"request approval", func(t *testing.T) {
			rule(t, db, "immutable approval", "UPDATE requests SET approver_id=$1 WHERE request_id=$2", identity.New(), reqApproved)
		}},
		{"request transition", func(t *testing.T) {
			rule(t, db, "invalid request transition", "UPDATE requests SET state='pending' WHERE request_id=$1", reqApproved)
		}},
		// Request constraints. A missing identity field makes the binding
		// comparison NULL, which only IS TRUE refuses.
		{"request binding identity", func(t *testing.T) {
			for _, drop := range []string{"id", "boot_id", "scope.owner_id"} {
				id := identity.New()
				sql, args := insertSQL("requests", append(request(id, "pending"), "binding", binding(id, "confirm", drop))...)
				rule(t, db, "requests_binding_identity", sql, args...)
			}
		}},
		{"request approved mode", func(t *testing.T) {
			for _, mode := range []string{"", "none"} {
				id := identity.New()
				sql, args := insertSQL("requests", append(append(request(id, "approved"), decided("owner_confirmation")...), "binding", binding(id, mode, ""))...)
				rule(t, db, "requests_approved_mode", sql, args...)
			}
		}},
		{"request expiry window", func(t *testing.T) {
			for _, expires := range []time.Duration{0, 5*time.Minute + time.Second} {
				sql, args := insertSQL("requests", append(request(identity.New(), "pending"), "expires_at", at(expires))...)
				rule(t, db, check("requests_check", "expires_at > created_at AND expires_at <= created_at + 300000000"), sql, args...)
			}
		}},
		{"request id format", func(t *testing.T) {
			id := "0000000g-0000-4000-8000-000000000000"
			sql, args := insertSQL("requests", request(id, "pending")...)
			// PostgreSQL stores the ID as a uuid, which refuses the text.
			rule(t, db, check("22P02", "length(request_id) = 36 AND request_id NOT GLOB"), sql, args...)
		}},
		// Guards and constraints on leases.
		{"lease binding/max_calls from NULL", func(t *testing.T) {
			rule(t, db, "immutable lease binding", "UPDATE leases SET max_calls=5 WHERE lease_id=$1", leaseCalls)
		}},
		{"lease binding/max_calls to NULL", func(t *testing.T) {
			rule(t, db, "immutable lease binding", "UPDATE leases SET max_calls=NULL WHERE lease_id=$1", leaseFree)
		}},
		{"lease counter", func(t *testing.T) {
			rule(t, db, "invalid admission counter", "UPDATE leases SET admitted_calls=admitted_calls+2 WHERE lease_id=$1", leaseCalls)
			rule(t, db, "invalid admission counter", "UPDATE leases SET state='revoked',ended_at=$1,admitted_calls=admitted_calls+1 WHERE lease_id=$2", at(5*time.Minute), leaseCalls)
		}},
		{"lease state and ended_at", func(t *testing.T) {
			want := check("leases_check2", "(state = 'active') = (ended_at IS NULL)")
			rule(t, db, want, "UPDATE leases SET state='revoked' WHERE lease_id=$1", leaseCalls)
			rule(t, db, want, "UPDATE leases SET ended_at=$1 WHERE lease_id=$2", at(5*time.Minute), leaseCalls)
		}},
		{"lease admitted within max", func(t *testing.T) {
			sql, args := insertSQL("leases", lease(identity.New(), reqSpare, 1, "admitted_calls", 2)...)
			rule(t, db, check("leases_check1", "admitted_calls >= 0 AND (max_calls IS NULL OR admitted_calls <= max_calls)"), sql, args...)
		}},
		{"lease expiry window", func(t *testing.T) {
			for _, expires := range []time.Duration{2 * time.Minute, time.Hour + 2*time.Minute + time.Second} {
				sql, args := insertSQL("leases", lease(identity.New(), reqSpare, nil, "expires_at", at(expires))...)
				rule(t, db, check("leases_check", "expires_at > activated_at AND expires_at <= activated_at + 3600000000"), sql, args...)
			}
		}},
		{"lease strict", func(t *testing.T) {
			if db.Driver() == "postgres" {
				t.Skip("PostgreSQL columns are typed")
			}
			sql, args := insertSQL("leases", lease(identity.New(), reqSpare, nil, "epoch", "one")...)
			rule(t, db, "cannot store TEXT value in INTEGER column leases.epoch", sql, args...)
		}},
		// Events.
		{"security events append only", func(t *testing.T) {
			rule(t, db, pick(db, "42501", "append-only security event"), "UPDATE security_events SET metadata=metadata")
		}},
		{"invocation events unique", func(t *testing.T) {
			sql, args := insertSQL("invocation_events", "owner_id", "alice", "event_id", identity.New(), "invocation_id", "0f000000-0000-4000-8000-000000000001",
				"event_type", "tool.dispatch.admitted", "occurred_at", at(4*time.Minute), "request_id", reqCalls, "lease_id", leaseCalls, "metadata", "{}")
			rule(t, db, pick(db, "invocation_events_owner_id_invocation_id_event_type_key",
				"UNIQUE constraint failed: invocation_events.owner_id, invocation_events.invocation_id, invocation_events.event_type"), sql, args...)
		}},
		// Vault.
		{"vault root insert", func(t *testing.T) {
			sql, args := insertSQL("vault_roots", "owner_id", "dave", "root_id", identity.New(), "root_version", 1, "wrapper_revision", 2)
			rule(t, db, "invalid initial vault root", sql, args...)
		}},
		{"credential head identity", func(t *testing.T) {
			// The revision moves too, so the version guard lets it through.
			rule(t, db, "immutable credential identity or tombstone", "UPDATE credential_heads SET connector_id=$1,revision=revision+1", identity.New())
		}},
		{"credential head delete", func(t *testing.T) {
			rule(t, db, "invalid credential deletion", "UPDATE credential_heads SET deleted_at=$1,revision=revision+1", at(0))
		}},
		{"credential head version", func(t *testing.T) {
			rule(t, db, "invalid credential version update", "UPDATE credential_heads SET revision=revision+2")
		}},
		{"credential epoch/destination to NULL", func(t *testing.T) {
			rule(t, db, "immutable credential epoch or invalid write count", "UPDATE credential_epochs SET destination=NULL,write_count=write_count+1")
		}},
		{"wrap count bound", func(t *testing.T) {
			// At the cap the update guard allows one more wrap; only the
			// CHECK refuses it.
			db.Seed(t, "vault_roots", "UPDATE vault_roots SET wrap_count=1048576 WHERE owner_id='alice'")
			rule(t, db, check("vault_roots_wrap_count_check", "wrap_count BETWEEN 0 AND 1048576"), "UPDATE vault_roots SET wrap_count=wrap_count+1 WHERE owner_id='alice'")
		}},
		// Approval policy.
		{"approval policy insert", func(t *testing.T) {
			sql, args := insertSQL("approval_policies", "owner_id", "dave", "mode", "confirm", "revision", 3, "changed_at", at(0), "changed_by", identity.New())
			rule(t, db, "invalid initial approval policy", sql, args...)
		}},
		{"approval policy update", func(t *testing.T) {
			rule(t, db, "invalid approval policy update", "UPDATE approval_policies SET revision=revision+2")
		}},
		// Catalog and history.
		{"connector tombstone", func(t *testing.T) {
			want := check("catalog_connectors_check", "(deleted_at IS NULL) = (name IS NOT NULL)")
			sql, args := insertSQL("catalog_connectors", "connector_id", identity.New(), "owner_id", "alice", "name", "gone", "auth_type", "none", "deleted_at", at(0), "sealed", sealed("t"))
			rule(t, db, want, sql, args...)
			sql, args = insertSQL("catalog_connectors", "connector_id", identity.New(), "owner_id", "alice", "name", nil, "auth_type", "none", "sealed", sealed("t"))
			rule(t, db, want, sql, args...)
		}},
		{"history schema version", func(t *testing.T) {
			want := check("history_events_check1", "(schema_version = 2) = (event_type IS NOT NULL AND invocation_id IS NOT NULL)")
			rule(t, db, want, copyHistory("owner_id,'h-v1',1,event_type,'inv-v1'"))
			rule(t, db, want, copyHistory("owner_id,'h-v2',2,NULL,NULL"))
		}},
		{"history events unique", func(t *testing.T) {
			rule(t, db, pick(db, "history_events_owner_id_invocation_id_event_type_key",
				"UNIQUE constraint failed: history_events.owner_id, history_events.invocation_id, history_events.event_type"),
				copyHistory("owner_id,'h-dup',schema_version,event_type,invocation_id"))
		}},
		{"history events append only", func(t *testing.T) {
			rule(t, db, pick(db, "42501", "append-only history"), "UPDATE history_events SET status=status")
		}},
	} {
		t.Run(c.name, c.fn)
	}

	// Rows are never deleted: PostgreSQL's runtime role has no DELETE
	// privilege, and SQLite has a guard per table. vault_roots,
	// credential_heads and credential_epochs always have rows referencing
	// them, so there only the guard's message tells it from a foreign key.
	never := pick(db, "42501", "rows are never deleted")
	for _, c := range []struct {
		table, where, want string
		args               []any
	}{
		{"owners", "owner_id='carol'", never, nil},
		{"requests", "request_id=$1", never, []any{reqFree}},
		{"leases", "lease_id=$1", never, []any{leaseFree}},
		{"vault_roots", "owner_id='alice'", never, nil},
		{"vault_wrapper_sets", "wrapper_revision=1", never, nil},
		{"credential_heads", "owner_id='alice'", never, nil},
		{"credential_epochs", "owner_id='alice'", never, nil},
		{"credential_versions", "revision=1", never, nil},
		{"approval_policies", "owner_id='alice'", never, nil},
		{"catalog_accounts", "owner_id='alice'", never, nil},
		{"catalog_access", "access_id='access-1'", never, nil},
		{"catalog_connectors", "owner_id='alice'", never, nil},
		{"history_tools", "owner_id='alice'", never, nil},
		{"history_events", "event_id='h1'", pick(db, "42501", "append-only history"), nil},
	} {
		t.Run("delete/"+c.table, func(t *testing.T) {
			rule(t, db, c.want, "DELETE FROM "+c.table+" WHERE "+c.where, c.args...)
		})
	}
}
