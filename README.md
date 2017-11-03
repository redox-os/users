# users

Redox OS APIs for accessing users and groups information.

High level APIs for things like:

- Getting the current process effective user ID.
- Getting the current process user ID.
- Getting the current process effective group ID.
- Getting the current process group ID.
- Getting the user information for a given user ID.
- Getting the group information for a given group ID.
- Getting the user information for a given username.
- Getting a group information for a given group name.

We recommend to user these APIs instead of directly manipulating
`/etc/group` and `etc/passwd` as this is an implementation detail and
might change in the future.

## Using users

Make sure you have Rust nightly.

Add `rust_users` to `Cargo.toml`:

```toml
[dependencies.rust_users]
git = "https://github.com/redox-os/users.git"
```

then import it in your main file:

```rust
extern crate rust_users;
```

And `rust_users` is now ready to roll!