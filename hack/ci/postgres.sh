#!/usr/bin/env bash
# ci-postgres: the store contract on a real PostgreSQL (fresh schema, upgrades from earlier
# schemas, concurrent writers, revision numbers, apply steps) and the Git job and record
# contracts, with the tests that take a database in internal/gitsync. SANDBOX_TEST_POSTGRES_URL
# names the database: an explicit input the provider maps its service to, e.g.
#   postgres://sandbox:sandbox@127.0.0.1:5432/sandbox_test?sslmode=disable
# The "no database configured" skip is turned into a failure, so a missing service never passes.
. "$(dirname "$0")/lib.sh"
cd "$ci_root"
[ -n "${SANDBOX_TEST_POSTGRES_URL:-}" ] || ci_die "postgres: SANDBOX_TEST_POSTGRES_URL is required (postgres://user:password@host:5432/db?sslmode=disable)"
export SANDBOX_TEST_POSTGRES_URL SANDBOX_TEST_REQUIRE_EXTERNAL=1
go test ./internal/store/ -count=1 -race -v
go test ./internal/gitsync/ -count=1 -race
ci_ok postgres
