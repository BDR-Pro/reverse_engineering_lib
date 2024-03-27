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

## Here's a brief overview of the modes it supports

### For `pe-header` Mode

Given a PE file, this mode prints out the basic PE header information:

```plaintext

$ cargo run -- pe-header path/to/pe_file.exe
PeHeaderInfo { machine: 34404, number_of_sections: 5 }

```

This output indicates that the PE file is for an x64 architecture (`machine: 34404` corresponds to AMD64) and contains 5 sections.

### For `elf-functions` Mode

Given an ELF file, this mode lists the names of functions found in the ELF file:

```plaintext

$ cargo run -- elf-functions path/to/elf_file
["main", "_start", "printf", "exit"]

```

This example output shows the ELF file contains functions like `main`, `_start`, `printf`, and `exit`.

### For `entropy` Mode

This mode calculates and displays the entropy of segments (or "windows") of a file, which can indicate its randomness:

```plaintext
$ cargo run -- entropy path/to/any_file
Offset: 0x0, Entropy: 7.95
Offset: 0x100, Entropy: 5.47
Offset: 0x200, Entropy: 3.58

```

Here, the entropy values are hypothetical and show that the file starts with high randomness (entropy close to 8), which decreases in later sections. High entropy could indicate compressed or encrypted data.

### Disassembler Mode

This mode disassembles the given binary file and prints the disassembled instructions:

```bash

0x14af: nop
0x14b0: call    0xcc30
0x14b5: cmp     eax, 0xa
0x14b8: je      0x14bf
0x14ba: cmp     eax, -1
0x14bd: jne     0x14b0
0x14bf: mov     eax, dword ptr [rbp - 4]
0x14c2: cmp     eax, dword ptr [rip + 0x424330]
0x14c8: jle     0x14da


```

This output shows the disassembled instructions at different memory addresses in the binary file.

```rust
use reverse_engineering_lib::disassemble;

fn main() {
    let file_path =
        "{your_binary_file_path_here.exe}";
    match disassemble(&file_path) {
        Ok(disassembly) => println!("{}", disassembly),
        Err(e) => eprintln!("Disassembly failed: {}", e),
    }
}


```

---

Happy reverse engineering! 🚀👨‍💻👩‍💻

Remember, with great power comes great responsibility. Use **reverse_engineering_lib** ethically and legally. Happy hacking! 🖥️🔐
