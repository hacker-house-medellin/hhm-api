Cargo.toml: main added hmac / hhm-interfaces / oresoftware-next-loggers and switched sea-orm to
default-features = false; this Dependabot PR raises the sea-orm requirement to 2.0. Kept main's dependency
set and feature shape and applied the version bump on top (sea-orm 2.0, default-features = false, same
features). Cargo.lock is refreshed with `cargo update -p sea-orm` and the build is gated with `cargo check`.
