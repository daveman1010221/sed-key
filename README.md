# sed-key

[![Crates.io](https://img.shields.io/crates/v/sed-key.svg)](https://crates.io/crates/sed-key)

`sed-key` is a Rust command-line tool for locking, unlocking, and querying the lock state of [NVMe Self-Encrypting Drives (SED)](https://wiki.archlinux.org/title/Self-encrypting_drives) using the TCG OPAL protocol under Linux. Its scope is intentionally limited and is intended for use in places like early stage boot environments. sed-key is designed to accept a key as a CLI argument.

It wraps the Linux `ioctl`s for OPAL discovery and lock/unlock, providing:

- **Discovery**: Check whether a drive supports OPAL/SED and parse the locking feature descriptor.
- **Locking/Unlocking**: Send the `OPAL_LOCK_UNLOCK` command with your Admin1 password.
- **CLI**: A `sed-key` binary to view lock status or unlock drives interactively.

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

When running under Miri or in CI, hardware IOCTLs are replaced by a fabricated discovery page.
Example:

```bash
MIRI_SED_LOCKED=1 cargo miri run -- status /dev/nvme0n1
```

This lets the parser and property-based tests run without touching real drives.

## License

Licensed under MIT.

## Links

- [TCG Storage Work Group](https://trustedcomputinggroup.org/work-groups/storage/)
- [**Linux SED OPAL Bindings Crate**](https://crates.io/crates/linux-sed-opal-sys)
- [**Homepage / Source Code**](https://github.com/daveman1010221/sed-key)
