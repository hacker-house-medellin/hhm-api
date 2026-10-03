# hacker-house-medellin/hhm-api#6 — build(deps): update sea-orm requirement from 1.1 to 2.0

head: dependabot/cargo/sea-orm-2.0  base: main  author: app/dependabot  updated: 2026-08-29T17:47:08Z
dir: /Users/maca5/codes/.claude-fleet/scratch/merge/hacker-house-medellin_hhm-api__6

## conflicted files
- Cargo.toml

## base (main) last 8 commits
4c01bbb Merge pull request #7 from hacker-house-medellin/dependabot/cargo/tower-http-0.7
077c9d7 Merge pull request #9 from hacker-house-medellin/feat/doorway-proof-json-v1
4a355a5 Merge pull request #8 from hacker-house-medellin/agent/hhm-hardening-20260824
a94b8c8 merge origin/main: keep auth/visitor hardening and current CORS pipeline plus later reservation hardening.
42283ea Merge pull request #10 from hacker-house-medellin/agent/fp-pass-3
bc36a17 Normalize reservations as a new value and parse CORS origins as a pipeline.
59c7948 feat(presence): add fail-closed doorway admission engine
6ceae08 fix(visitor): bind QR codes to access audience

## head (dependabot/cargo/sea-orm-2.0) last 8 commits
d854383 build(deps): update sea-orm requirement from 1.1 to 2.0
db16beb Merge branch 'main' of github.com:hacker-house-medellin/hhm-api
4320823 Merge branch 'main' of https://github.com/hacker-house-medellin/hhm-api
480bc3e Merge branch 'main' of github.com:hacker-house-medellin/hhm-api
a90f1db fix: harden reservation input and CORS boundaries
c185f82 chore: ignore tmp/temp worktree scratch directories
4bfb2a2 Merge remote:agent/zed-dependency-graph-20260804 into main with canonical policy reconciliation
92e2815 Prefer primary branches and avoid agent worktrees

## merge-base: db16beb7829c4cc6685184bef9c4481c6b996012

## PR diff stat (merge-base..head)
 Cargo.toml | 2 +-
 1 file changed, 1 insertion(+), 1 deletion(-)

## base diff stat (merge-base..base)
 .dockerignore                         |   11 +
 .env.example                          |   13 +
 .envrc                                |    9 +
 .gitattributes                        |    2 +
 .github/workflows/secrets-audit.yml   |   41 +
 .gitignore                            |   31 +
 .just/dotenv.py                       |   87 +
 .just/env.just                        |  461 ++++++
 .nix/README.md                        |    6 +
 .nix/flake.nix                        |   55 +
 .sops.yaml                            |   58 +
 Cargo.lock                            | 2938 +++++++++++++++++++++++++++++++++
 Cargo.toml                            |   10 +-
 Dockerfile                            |   15 +-
 README.md                             |   53 +-
 docs/surveillance-privacy-boundary.md |   68 +
 env/README.md                         |  156 ++
 env/enc/dev.env.enc                   |   21 +
 env/enc/prod.env.enc                  |   19 +
 justfile                              |   57 +
 scripts/sops-entrypoint.sh            |   62 +
 scripts/verify_repo.py                |   18 +-
 shell                                 |   11 +
 src/auth.rs                           |  228 +++
 src/main.rs                           |  363 +++-
 src/observability.rs                  |   78 +
 src/presence.rs                       |  568 +++++++
 src/visitor.rs                        |  711 ++++++++
 28 files changed, 6097 insertions(+), 53 deletions(-)

## merge output
Auto-merging Cargo.toml
CONFLICT (content): Merge conflict in Cargo.toml
Automatic merge failed; fix conflicts and then commit the result.
