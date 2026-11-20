package postgres

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/asadbekabdulboqiyev/sift/internal/store/memstore"
)

// TestMapErrNormalisesDriverErrors exercises every translation branch without
// opening a connection: all inputs are constructed in-process.
func TestMapErrNormalisesDriverErrors(t *testing.T) {
	base := errors.New("driver: connection reset")
	unique := &pgconn.PgError{Code: sqlStateUniqueViolation, Message: "duplicate key"}
	foreign := &pgconn.PgError{Code: sqlStateForeignKeyViolation, Message: "fk violation"}
	otherCode := &pgconn.PgError{Code: "42601", Message: "syntax error"}

	cases := []struct {
		name         string
		err          error
		wantNotFound bool
		wantConflict bool
		wantIs       error
	}{
		{name: "nil stays nil", err: nil},
		{name: "no rows becomes not found", err: pgx.ErrNoRows, wantNotFound: true, wantIs: pgx.ErrNoRows},
		{name: "unique violation becomes conflict", err: unique, wantConflict: true, wantIs: ErrConflict},
		{name: "wrapped unique violation becomes conflict", err: fmt.Errorf("exec: %w", unique), wantConflict: true, wantIs: ErrConflict},
		{name: "foreign key violation becomes not found", err: foreign, wantNotFound: true, wantIs: ErrNotFound},
		{name: "wrapped foreign key violation becomes not found", err: fmt.Errorf("exec: %w", foreign), wantNotFound: true, wantIs: ErrNotFound},
		{name: "unrelated pg error is preserved", err: otherCode, wantIs: otherCode},
		{name: "unrelated error is preserved", err: base, wantIs: base},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Act
			got := mapErr("unit-op", tc.err)

			// Assert
			if tc.err == nil {
				if got != nil {
					t.Fatalf("mapErr(unit-op, nil) = %v, want nil", got)
				}
				return
			}
			if got == nil {
				t.Fatal("mapErr returned nil for a non-nil error")
			}
			if !strings.Contains(got.Error(), "unit-op") {
				t.Errorf("mapErr error %q does not name the operation", got)
			}
			if errors.Is(got, ErrNotFound) != tc.wantNotFound {
				t.Errorf("errors.Is(%v, ErrNotFound) = %v, want %v", got, errors.Is(got, ErrNotFound), tc.wantNotFound)
			}
			if errors.Is(got, ErrConflict) != tc.wantConflict {
				t.Errorf("errors.Is(%v, ErrConflict) = %v, want %v", got, errors.Is(got, ErrConflict), tc.wantConflict)
			}
			if tc.wantIs != nil && !errors.Is(got, tc.wantIs) {
				t.Errorf("errors.Is(%v, %v) = false, want true", got, tc.wantIs)
			}
		})
	}
}

// TestMapErrPreservesDriverError pins the documented ErrConflict contract:
// translating a driver error to a sentinel must NOT swallow the original
// *pgconn.PgError, so callers can still inspect SQLSTATE and constraint names
// through errors.As. This regresses the bug where mapErr wrapped only the
// sentinel and errors.As(err, &pgErr) returned false.
func TestMapErrPreservesDriverError(t *testing.T) {
	unique := &pgconn.PgError{
		Code:           sqlStateUniqueViolation,
		Message:        "duplicate key value violates unique constraint",
		ConstraintName: "tenants_slug_key",
	}
	foreign := &pgconn.PgError{
		Code:           sqlStateForeignKeyViolation,
		Message:        "insert violates foreign key constraint",
		ConstraintName: "findings_tenant_id_fkey",
	}

	cases := []struct {
		name           string
		err            error
		wantSentinel   error
		wantCode       string
		wantConstraint string
	}{
		{name: "unique violation", err: unique, wantSentinel: ErrConflict, wantCode: sqlStateUniqueViolation, wantConstraint: "tenants_slug_key"},
		{name: "wrapped unique violation", err: fmt.Errorf("exec: %w", unique), wantSentinel: ErrConflict, wantCode: sqlStateUniqueViolation, wantConstraint: "tenants_slug_key"},
		{name: "foreign key violation", err: foreign, wantSentinel: ErrNotFound, wantCode: sqlStateForeignKeyViolation, wantConstraint: "findings_tenant_id_fkey"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := mapErr("create", tc.err)

			// The sentinel stays reachable...
			if !errors.Is(got, tc.wantSentinel) {
				t.Errorf("errors.Is(%v, %v) = false, want true", got, tc.wantSentinel)
			}

			// ...and so does the original driver error.
			var pgErr *pgconn.PgError
			if !errors.As(got, &pgErr) {
				t.Fatalf("errors.As(%v, &pgErr) = false, want true", got)
			}
			if pgErr.Code != tc.wantCode {
				t.Errorf("PgError.Code = %q, want %q", pgErr.Code, tc.wantCode)
			}
			if pgErr.ConstraintName != tc.wantConstraint {
				t.Errorf("PgError.ConstraintName = %q, want %q", pgErr.ConstraintName, tc.wantConstraint)
			}
		})
	}
}

// TestErrNotFoundMatchesPublicSentinels verifies the cross-package contract:
// callers using memstore's sentinel, pgx's ErrNoRows or this package's own
// sentinel must all recognise the same not-found condition.
func TestErrNotFoundMatchesPublicSentinels(t *testing.T) {
	cases := []struct {
		name   string
		target error
		want   bool
	}{
		{name: "own sentinel", target: ErrNotFound, want: true},
		{name: "memstore sentinel", target: memstore.ErrNotFound, want: true},
		{name: "pgx no rows", target: pgx.ErrNoRows, want: true},
		{name: "conflict is not not-found", target: ErrConflict, want: false},
		{name: "unrelated error", target: errors.New("other"), want: false},
		{name: "wrapped target is not itself a sentinel", target: fmt.Errorf("wrap: %w", pgx.ErrNoRows), want: false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := errors.Is(ErrNotFound, tc.target); got != tc.want {
				t.Fatalf("errors.Is(ErrNotFound, %v) = %v, want %v", tc.target, got, tc.want)
			}
		})
	}

	// The same must hold once the error has been wrapped by mapErr.
	mapped := mapErr("get", pgx.ErrNoRows)
	for _, sentinel := range []error{ErrNotFound, memstore.ErrNotFound, pgx.ErrNoRows} {
		if !errors.Is(mapped, sentinel) {
			t.Errorf("errors.Is(mapped, %v) = false, want true", sentinel)
		}
	}
}

// TestIsPgCodeHandlesWrappedDriverErrors covers the SQLSTATE helper directly,
// including mismatched codes and non-driver errors.
func TestIsPgCodeHandlesWrappedDriverErrors(t *testing.T) {
	cases := []struct {
		name string
		err  error
		code string
		want bool
	}{
		{name: "nil error", err: nil, code: sqlStateUniqueViolation, want: false},
		{name: "matching code", err: &pgconn.PgError{Code: sqlStateUniqueViolation}, code: sqlStateUniqueViolation, want: true},
		{name: "matching code through wrapping", err: fmt.Errorf("outer: %w", &pgconn.PgError{Code: sqlStateForeignKeyViolation}), code: sqlStateForeignKeyViolation, want: true},
		{name: "different code", err: &pgconn.PgError{Code: sqlStateForeignKeyViolation}, code: sqlStateUniqueViolation, want: false},
		{name: "plain error", err: errors.New("plain"), code: sqlStateUniqueViolation, want: false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isPgCode(tc.err, tc.code); got != tc.want {
				t.Fatalf("isPgCode(%v, %q) = %v, want %v", tc.err, tc.code, got, tc.want)
			}
		})
	}
}

// TestNewIDFormatAndUniqueness checks the generated primary keys that every
// Create method relies on when the caller supplies an empty ID.
func TestNewIDFormatAndUniqueness(t *testing.T) {
	cases := []struct {
		prefix string
		wantRE string
	}{
		{prefix: "k", wantRE: `^k_[0-9a-f]{32}$`},
		{prefix: "tenant", wantRE: `^tenant_[0-9a-f]{32}$`},
	}

	for _, tc := range cases {
		t.Run(tc.prefix, func(t *testing.T) {
			re := regexp.MustCompile(tc.wantRE)
			seen := make(map[string]bool)
			for i := 0; i < 32; i++ {
				id := newID(tc.prefix)
				if !re.MatchString(id) {
					t.Fatalf("newID(%q) = %q, want %s", tc.prefix, id, tc.wantRE)
				}
				if seen[id] {
					t.Fatalf("newID(%q) produced duplicate %q", tc.prefix, id)
				}
				seen[id] = true
				if _, err := hex.DecodeString(strings.TrimPrefix(id, tc.prefix+"_")); err != nil {
					t.Fatalf("newID(%q) suffix is not hex: %v", tc.prefix, err)
				}
			}
		})
	}
}

// TestTimestampAndStringHelpers pins the NULL mapping used by every insert.
func TestTimestampAndStringHelpers(t *testing.T) {
	t.Run("zero timestamp maps to nil", func(t *testing.T) {
		if got := tsOrNil(time.Time{}); got != nil {
			t.Fatalf("tsOrNil(zero) = %v, want nil", got)
		}
	})

	t.Run("timestamp is converted to UTC", func(t *testing.T) {
		// Arrange: +02:00 zone with a fixed instant.
		loc := time.FixedZone("UTC+2", 2*60*60)
		in := time.Date(2026, 11, 20, 12, 30, 0, 0, loc)

		// Act
		got := tsOrNil(in)

		// Assert
		if got == nil {
			t.Fatal("tsOrNil(non-zero) = nil")
		}
		if !got.Equal(in) {
			t.Fatalf("tsOrNil(%v) = %v, want the same instant", in, *got)
		}
		if got.Location() != time.UTC {
			t.Fatalf("tsOrNil location = %v, want UTC", got.Location())
		}
	})

	t.Run("empty string maps to nil", func(t *testing.T) {
		if got := nullIfEmpty(""); got != nil {
			t.Fatalf("nullIfEmpty(empty) = %v, want nil", got)
		}
	})

	t.Run("non-empty string is preserved", func(t *testing.T) {
		got := nullIfEmpty("203.0.113.7")
		if got == nil || *got != "203.0.113.7" {
			t.Fatalf("nullIfEmpty = %v, want pointer to 203.0.113.7", got)
		}
	})
}

// TestOpenRejectsInvalidDSNWithoutConnecting covers both early-return branches
// of Open. Both inputs fail before pgxpool attempts a connection, so the test
// needs neither a server nor a timeout.
func TestOpenRejectsInvalidDSNWithoutConnecting(t *testing.T) {
	cases := []struct {
		name    string
		dsn     string
		wantMsg string
	}{
		{name: "empty DSN", dsn: "", wantMsg: "empty DSN"},
		{name: "malformed keyword DSN", dsn: "not a valid dsn", wantMsg: "parse dsn"},
		{name: "malformed URL escape", dsn: "postgres://user@%zz/db", wantMsg: "parse dsn"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Act
			db, err := Open(context.Background(), tc.dsn)

			// Assert
			if db != nil {
				t.Fatalf("Open(%q) returned a non-nil DB with error %v", tc.dsn, err)
			}
			if err == nil {
				t.Fatalf("Open(%q) succeeded, want error", tc.dsn)
			}
			if !strings.Contains(err.Error(), tc.wantMsg) {
				t.Fatalf("Open(%q) error = %v, want it to contain %q", tc.dsn, err, tc.wantMsg)
			}
		})
	}
}

// TestCloseAndPoolOnZeroValueDB checks the no-connection paths used by cleanup
// code and health probes when Open was never called.
func TestCloseAndPoolOnZeroValueDB(t *testing.T) {
	var nilDB *DB
	if err := nilDB.Close(); err != nil {
		t.Fatalf("(*DB)(nil).Close() = %v, want nil", err)
	}

	zero := &DB{}
	if err := zero.Close(); err != nil {
		t.Fatalf("(&DB{}).Close() = %v, want nil", err)
	}
	if p := zero.Pool(); p != nil {
		t.Fatalf("(&DB{}).Pool() = %p, want nil", p)
	}
}

// TestMigrationTableInvariants guards the append-only, idempotent migration
// contract using only the embedded SQL text.
func TestMigrationTableInvariants(t *testing.T) {
	if len(migrations) == 0 {
		t.Fatal("migrations is empty")
	}

	seen := make(map[string]bool)
	for i, m := range migrations {
		if m.version == "" {
			t.Errorf("migrations[%d] has an empty version", i)
		}
		if seen[m.version] {
			t.Errorf("migrations[%d] repeats version %q", i, m.version)
		}
		seen[m.version] = true
		if strings.TrimSpace(m.sql) == "" {
			t.Errorf("migration %q has empty SQL", m.version)
		}
		if i == 0 && m.version != "0001_init" {
			t.Errorf("first migration = %q, want 0001_init", m.version)
		}
	}

	for _, stmt := range strings.Split(schemaSQL, "\n") {
		trimmed := strings.ToUpper(strings.TrimSpace(stmt))
		if strings.HasPrefix(trimmed, "CREATE TABLE") || strings.HasPrefix(trimmed, "CREATE INDEX") {
			if !strings.Contains(trimmed, "IF NOT EXISTS") {
				t.Errorf("embedded schema statement is not idempotent: %s", stmt)
			}
		}
	}
	if !strings.Contains(strings.ToUpper(createMigrationsTable), "IF NOT EXISTS") {
		t.Error("createMigrationsTable is not idempotent")
	}
}
