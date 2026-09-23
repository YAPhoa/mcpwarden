# Continuous integration

`.github/workflows/ci.yml` runs on main pushes, pull requests, merge queues,
manual dispatch and a weekly schedule. It needs no repository secrets or live
service credentials. Use **Required checks** from the **CI** workflow as the
required status in the main-branch ruleset; it fails if any mandatory job fails,
is cancelled or is skipped. The private repository is
[YAPhoa/mcpwarden](https://github.com/YAPhoa/mcpwarden).

The [initial hosted CI run](https://github.com/YAPhoa/mcpwarden/actions/runs/35825326621)
passed every mandatory job. Actions and Dependabot vulnerability alerts are
enabled. Repository workflow permissions default to read-only, without permission
to approve pull requests. GitHub returned HTTP 403 when checking repository
rulesets: this account needs GitHub Pro to enforce branch rules on this private
repository. Until that is available, check **Required checks** manually before
merging. See [protected-branch availability](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-protected-branches/about-protected-branches).
CodeQL is configured but skipped while private Code Security access and the
explicit opt-in are absent.

| Check | What it runs |
|---|---|
| Go and PostgreSQL | gofmt; module tidy/verification; original spec and vendored crypto hashes; build; vet; full race suite with PostgreSQL enabled and Node available; CGO-disabled build/JSON/storage tests; two bounded parser fuzz runs. |
| UI and vault (Chromium, Firefox, WebKit) | Locked development dependencies with lifecycle scripts disabled; UI/crypto tests; npm high/critical advisory check; real worker/KDF/recovery/lock/CSP tests in each browser engine. |
| Security and workflow checks | actionlint (including ShellCheck when present on the runner), reachable Go vulnerability scanning, and redacted full Git history scanning with Gitleaks. |
| Container build and smoke | Separate gateway/UI images; isolated deployment with generated fixture credentials; health, API authentication/no-store, static assets and worker MIME/CSP checks; fixture volume cleanup. |
| CodeQL | Additional Go and JavaScript security-extended analysis on public repositories, or private repositories with Code Security enabled and `ENABLE_CODEQL=true`. Separate from the mandatory CI gate. |

Actions use full commit pins with release comments. The workflow token defaults
to read-only contents, checkout does not retain Git credentials, and tests use
`pull_request` rather than privileged `pull_request_target`. CodeQL alone receives
security-report write permission. Dependencies are not cached across these jobs.
No workflow builds from untrusted PR input in a production environment or deploys
the application.

Go is pinned in `.go-version` to match the Docker build; `.node-version` selects
Node 24. The UI's `package-lock.json` pins Playwright and its browser revisions.
Playwright is development-only: the nginx image copies static files, and its
build context excludes installed test dependencies. The Argon2 asset remains a
separate reviewed, vendored dependency with hashes and provenance.

Dependabot proposes weekly GitHub Actions, Go module, UI npm and Dockerfile
updates. Review security CLI versions, the PostgreSQL fixture image, `.go-version`,
and vendored Argon2 releases explicitly; they are not all package-manager entries.
Follow the original spec's dependency review and browser qualification gates.

## Reproduce locally

Run the following from the repository root, using the pinned Go/Node versions:

```sh
go build ./...
go vet ./...
go mod tidy -diff
go mod verify
python3 scripts/ci/integrity.py

docker compose -p mcpwarden-security-test -f compose.postgres-test.yaml up -d --wait
export MCPWARDEN_TEST_DATABASE_URL='postgres://mcpwarden_migrator:mcpwarden-test-only@127.0.0.1:55432/mcpwarden_security_test?sslmode=disable'
go test -race -count=1 ./...

npm ci --prefix ui --ignore-scripts
npm --prefix ui test
npm audit --prefix ui --audit-level=high
ui/node_modules/.bin/playwright install --with-deps chromium firefox webkit
VAULT_BROWSER=chromium npm --prefix ui run test:browser
VAULT_BROWSER=firefox npm --prefix ui run test:browser
VAULT_BROWSER=webkit npm --prefix ui run test:browser

# Builds and removes only its own uniquely named synthetic fixture.
python3 scripts/ci/containers.py

go run github.com/rhysd/actionlint/cmd/actionlint@v1.7.12
go run golang.org/x/vuln/cmd/govulncheck@v1.8.0 ./...
go run github.com/zricethezav/gitleaks/v8@v8.30.1 git --redact --no-banner --log-opts='--all'
```

The PostgreSQL credentials above are deliberately public test values. That
fixture remains separate from the application volume. PostgreSQL integration
checks create disposable databases/roles; CI supplies the database URL so those
checks cannot silently skip due to missing configuration. Browser tests use only
synthetic inputs and a loopback static server. They do not substitute for complete
owner UI flows, mobile-device measurements or an independent security review.

References: [GitHub's Go workflow documentation](https://docs.github.com/en/actions/tutorials/build-and-test-code/go),
[Playwright CI setup](https://playwright.dev/docs/ci),
[Gitleaks CLI](https://github.com/gitleaks/gitleaks), and
[CodeQL setup](https://docs.github.com/en/code-security/code-scanning/creating-an-advanced-setup-for-code-scanning/setting-up-advanced-setup-for-code-scanning).
