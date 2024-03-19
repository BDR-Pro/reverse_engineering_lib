# Reverse Engineering Lib 🕵️‍♂️🔍

Welcome to **reverse_engineering_lib**, your go-to Rust crate for peeling back the layers of binaries and understanding their innards! Whether you're a cybersecurity enthusiast, a malware analyst, or just plain curious about what makes executables tick, this crate has got your back. 

## Features 🌟

- **Entropy Calculation**: Get a sense of the randomness within your binary, a vital clue in spotting packed or encrypted sections.
- **Color-Based Hex Visualization**: Turn those drab hex dumps into a vibrant array of colors, because who said reverse engineering couldn't be a visual treat?
- **Detailed PE Analysis**: Dive deep into Portable Executable files, extracting juicy details like entry points, section headers, and import/export tables.

### Getting Started 🚀

First things first, you'll need Rust installed. If you haven't already, head on over to [rustup.rs](https://rustup.rs/) and follow the instructions.

Once Rust is ready to go, clone the repo and navigate into your project directory:

```bash
git clone https://github.com/bdr-pro/reverse_engineering_lib.git
cd reverse_engineering_lib
```

#### Usage 🛠

Calculating the entropy of a binary is as simple as:

```rust

let entropy = calculate_entropy("path/to/your/binary.exe").unwrap();
println!("Entropy: {}", entropy);
```

For a color-based perspective of your binary:

```rust
let color_data = color_based_hex("path/to/binary.exe").unwrap();
// Implement your logic to visualize color_data
```

And to extract detailed PE information:

```rust
let details = extract_detail_exe("path/to/binary.exe").unwrap();
for (key, value) in details.iter() {
    println!("{}: {}", key, value);
}
```

### Cli Mode 🖥️

The main function is in the `main.rs` file. It is a showcase of the library's capabilities by using the library's functions to analyze a binary file in cli mode.

### Contributing 🤝

Got ideas on how to make **reverse_engineering_lib** even better? Pull requests are more than welcome! Whether it's adding new features, improving documentation, or fixing bugs, your contributions are what make the open-source community amazing.

### License 📜

**reverse_engineering_lib** is distributed under the MIT License. See `LICENSE` for more information.

### Acknowledgments 💖

Big shoutout to the developers of the Rust programming language, the creators of the `sha2`, `rand`, and `goblin` crates, and everyone in the cybersecurity community who shares their knowledge and tools. You rock!

### Example `main.rs` 📂

For a practical example of how to use **reverse_engineering_lib**, check out the provided `main.rs` file in the repository. It's a ready-to-run showcase of the library's capabilities.

---

Happy reverse engineering! 🚀👨‍💻👩‍💻

Remember, with great power comes great responsibility. Use **reverse_engineering_lib** ethically and legally. Happy hacking! 🖥️🔐