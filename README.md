# sed-key

[![Crates.io](https://img.shields.io/crates/v/sed-key.svg)](https://crates.io/crates/sed-key)

`sed-key` is a Rust command-line tool **and reusable library** for locking, unlocking, and querying the lock state of [NVMe Self-Encrypting Drives (SED)](https://wiki.archlinux.org/title/Self-encrypting_drives) using the TCG OPAL protocol under Linux.

It’s intentionally minimal — ideal for early-boot or recovery environments — and supports both direct CLI use and programmatic invocation from other Rust code.

It wraps the Linux `ioctl`s for OPAL discovery and lock/unlock, providing:

- **Discovery**: Check whether a drive supports OPAL/SED and parse the locking feature descriptor.
- **Locking/Unlocking**: Send the `OPAL_LOCK_UNLOCK` command with your Admin1 password.
- **CLI**: A `sed-key` binary to view lock status or unlock drives interactively.
- **Library API:** Call `do_lock`, `do_unlock`, or `do_status` directly from your own code.
- **Mock Backend:** Built-in simulator for hardware-free testing.
- **Feature-Gated Real Hardware Tests:** Enable `--features real-hardware` for integration on test drives.

---

## ⚠️ Safety Warning

This software talks directly to your block devices using raw IOCTLs.  
Mistakes **can lock you out of your drive, or even crash a running kernel**.
You run this at your own risk.

---

## Installation

With Cargo:

```bash
cargo install sed-key
```

## CLI Usage

### Check lock status of a device

```bash
sudo sed-key status /dev/nvme0n1
```

This prints the parsed OPAL locking feature flags and whether the device is locked.

### Unlock a device

Pass the device path and optionally a password argument:

```bash
sudo sed-key unlock /dev/nvme0n1 mypassword
```

### Lock a device again

Similarly, to lock the device:

```bash
sudo sed-key lock /dev/nvme0n1 mypassword
```

### Noninteractive / scripting

All commands exit with nonzero on error so you can use them in shell scripts:

```bash
# Example: unlock with key from a file if the drive reports locked
if sudo sed-key status /dev/nvme0n1 | grep -q "LOCKED"; then
  sudo sed-key unlock /dev/nvme0n1 "$(cat /etc/keys/nvme0n1.key)"
fi

# Or perhaps:

# Use sed-key directly; password piped on stdin
if ! echo -n "$PW" | sed-key unlock "$dev" -; then
  rc=$?
  echo "ERROR: unlock failed for $dev (rc=$rc)" >&2
  exit $rc
fi
```

## Testing

All tests run safely without touching hardware by default:

```bash
cargo test
```

Property-based tests and regression corpus ensure deterministic runs.

For real hardware tests, explicitly enable:

```bash
cargo test --features real-hardware -- --ignored
```

Required environment:

```bash
export SED_KEY_TEST_DEV=/dev/nvme1
export SED_KEY_TEST_PW=mysecret
```

Never run these on a mounted or production drive.

When running under Miri or in CI, hardware IOCTLs are replaced by a fabricated discovery page.
Example:

```bash
MIRI_SED_LOCKED=1 cargo miri run -- status /dev/nvme0n1
```

This lets the parser and property-based tests run without touching real drives.

## Building From Source

### Using Cargo (standard build)

If you have Rust installed, you can build and run directly:

```bash
git clone https://github.com/daveman1010221/sed-key.git
cd sed-key
cargo build --release
```

### Using Nix (reproducible build)

If you have Nix installed with flakes enabled:

```bash
git clone https://github.com/daveman1010221/sed-key.git
cd sed-key
nix build .#default
```

This Nix build performs a fully offline, reproducible release build of `sed-key`.

## 🧩 Library Integration Example

```rust
use sed_key::{do_status, do_unlock, use_mock_backend};

fn main() -> anyhow::Result<()> {
    use_mock_backend();
    do_unlock("/dev/nvme0".into(), Some("pw".into()))?;
    do_status("/dev/nvme0".into())?;
    Ok(())
}
```

This allows scripting or testing drive control directly from Rust code.

## License

Licensed under MIT.

## Links

- [TCG Storage Work Group](https://trustedcomputinggroup.org/work-groups/storage/)
- [**Linux SED OPAL Bindings Crate**](https://crates.io/crates/linux-sed-opal-sys)
- [**Homepage / Source Code**](https://github.com/daveman1010221/sed-key)
