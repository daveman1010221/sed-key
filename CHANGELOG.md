## [0.1.3] - 2025-10-18

### 🚀 Features

- *(opal)* Introduce secure key handling and structured feature parsing

### 🚜 Refactor

- *(actions)* Simplify key input handling and integrate feature display

### 🧪 Testing

- *(proptest)* Add regression corpus for deterministic replay

### ⚙️ Miscellaneous Tasks

- *(gitignore)* Ignore local authorized_keys file
- *(nix)* Bump nixpkgs and crate version in flake
## [0.1.2] - 2025-10-14

### 🐛 Bug Fixes

- *(opal)* Keep file handle alive during ioctl to prevent EBADF
## [unreleased]

### ⚙️ Miscellaneous Tasks

- *(release)* Update CHANGELOG for 0.1.0
- *(docs)* Update changelog for 0.1.0 release
- *(release)* Update the comments for docs.rs
## [0.1.0] - 2025-09-22

### 🚀 Features

- *(status)* Add lock status check to avoid using nvme sed at all
- *(opal)* Add sed discover feature to simplify/strengthen early boot parser failures
- *(discover)* Add lock discovery and tests

### ⚙️ Miscellaneous Tasks

- *(docs)* Update README, add a LICENSE, generate a changelog
- *(docs)* Update README, add a section on build instructions
