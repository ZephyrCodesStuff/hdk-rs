<div align="center">

  <h1>hdk-rs</h1>

  <p>
    <strong>A complete, low-level, idiomatic Rust library for PlayStation Home development.</strong>
  </p>

  <p>
    <a href="https://github.com/ZephyrCodesStuff/hdk-rs/actions"><img src="https://img.shields.io/github/actions/workflow/status/ZephyrCodesStuff/hdk-rs/clippy.yml?branch=main&style=flat-square" alt="Build Status"></a>
    <!-- We are not currently on crates.io
    <a href="https://crates.io/crates/hdk-rs"><img src="https://img.shields.io/crates/v/hdk-rs?style=flat-square" alt="Crates.io version"></a>
    <a href="https://docs.rs/hdk-rs"><img src="https://img.shields.io/docsrs/hdk-rs?style=flat-square" alt="Docs.rs"></a>
    -->
    <a href="#license"><img src="https://img.shields.io/badge/license-AGPLv3-blue?style=flat-square" alt="License"></a>
  </p>

</div>

---

## 🌟 Authors

- [@zeph](https://github.com/ZephyrCodesStuff) (that's me!)

### Acknowledgements

- [@I-Knight-I](https://github.com/I-Knight-I) for their massive help with the cryptographic implementations, the compression algorithms and other miscellaneous bits of knowledge
- [@AgentDark447](https://github.com/GitHubProUser67) for their open-source software, allowing me to learn about the SHARC archive format
- @hykem for their efforts in reverse engineering the PS3 file formats such as NPD and SCE

## 📖 Overview

**hdk-rs** is a modular, low-level toolchain for interacting with PlayStation Home and PS3 file formats. Built with pure Rust, it focuses on safety, performance, and ergonomic usage. 

Unlike legacy C tools, `hdk-rs` leverages Rust's type system and traits. Readers and Writers implement standard `std::io::Read`, `Write`, and `Seek` traits, allowing for seamless streaming and composition.

> ⚠️ **Status: Work In Progress** > This library is currently under active construction. Expect breaking changes. The code is strictly linted to ensure high quality as the API stabilizes.

## 📦 The Ecosystem

`hdk-rs` is designed to be **modular**. You only pay for what you use. The library is split into individual crates, allowing you to only include the logic required for your specific needs.

| Crate | Description |
| :--- | :--- |
| **[`hdk-secure`](./hdk-secure)** | Implementation of algorithms from Sony's `libsecure`. Supports **XTEA** and **Blowfish**. Fully compatible with the [RustCrypto](https://github.com/RustCrypto) ecosystem. |
| **[`hdk-archive`](./hdk-archive)** | Reader/Writer support for **BAR** and **SHARC** PlayStation Home archives. Implements standard IO traits for maximum flexibility. |
| **[`hdk-sdat`](./hdk-sdat)** | Full support for the Sony **SDATA** format. Unpack, repack, and stream data efficiently. |
| **[`hdk-firmware`](./hdk-firmware)** | Handle **PUP** containers and **SCE** file encryption/decryption (used in system updates like `PS3UPDAT.PUP`). |
| **[`hdk-comp`](./hdk-comp)** | Implementations of **EdgeLZMA** and **EdgeZlib**. Deeply integrated with IO traits to allow streaming composition with crypto modules. |
| **[`hdk-mdl`](./hdk-mdl)** | Read PlayStation Home **MDL** (`HM`) model files. Supports export to JSON for easy inspection, via the `export` feature flag. |

## 💿 Installation

The crates are currently hosted on GitHub. To use them, add the specific crate you need to your Cargo.toml using a git dependency. Since this is a monorepo, use the same repository URL for any crate in the ecosystem.

```toml
[dependencies]
# Example: Using the crypto and archive modules
hdk-secure = { git = "https://github.com/ZephyrCodesStuff/hdk-rs", branch = "main" }
hdk-archive = { git = "https://github.com/ZephyrCodesStuff/hdk-rs", branch = "main" }
```

## 💛 Contributions

Contributions are welcome! Since this project aims for stability and correctness:
1. Please ensure `cargo clippy` passes.
2. Ensure no functionality is added without corresponding tests.
3. Do not go out-of-scope. Your PR should only touch what is relevant to your addition.
4. Make sure your PR contains all the details needed to know what you're changing and why.

Note: although not strictly enforced, running `clippy::pedantic` every now and then is not a bad idea.

## 📄 License

This project is licensed under the **GNU Affero General Public License v3.0 (AGPL-3.0)**.

**What this means:**
* ✅ **You can** use this library to build open source tools.
* ✅ **You can** modify the library to suit your needs.
* 🛑 **If you use this library** in a networked service (e.g., a backend server interacting with clients), you **must** make the source code of that service available to users.
* 🛑 **If you distribute** a binary that links to this library, you **must** provide the source code for your application.

See [LICENSE](LICENSE) for more details.
