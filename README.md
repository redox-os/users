# redox_users

Redox OS APIs for accessing users and groups information.

High level APIs for:

- Getting the current process effective user ID.
- Getting the current process user ID.
- Getting the current process effective group ID.
- Getting the current process group ID.
- Getting the user information for a given user ID.
- Getting the group information for a given group ID.
- Getting the user information for a given username.
- Getting a group information for a given group name.
- Iterating over all the users on the system.
- Iterating over all the groups on the system
- Adding a user
- Adding a group
- Getting an unused gid

We recommend to use these APIs instead of directly manipulating the
`/etc/group` and `/etc/passwd` as this is an implementation detail and
might change in the future.

## Using redox_users

Make sure you have Rust nightly.

Add `redox_users` to `Cargo.toml`:

```toml
[dependencies.redox_users]
git = "https://github.com/redox-os/users.git"
```

then import it in your main file:

```rust
extern crate redox_users;
```

And `redox_users` is now ready to roll!
