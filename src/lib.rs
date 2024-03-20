use goblin::elf::Elf;
use goblin::pe::PE;
use rand::prelude::SliceRandom;
use rand::thread_rng;
use rand::Rng;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::env;
use std::error::Error;
use std::fs;
use std::fs::File;
use std::io::{self, Read};
use std::process;
pub fn calculate_entropy(file_path: &String) -> io::Result<f64> {
    let mut file = File::open(file_path)?;
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer)?;

    let total_bytes = buffer.len();
    let mut frequency_map = HashMap::new();

    // Count the frequency of each byte
    for &byte in &buffer {
        *frequency_map.entry(byte).or_insert(0) += 1;
    }

    // Calculate the entropy
    let entropy = frequency_map.values().fold(0.0, |acc, &count| {
        let probability = count as f64 / total_bytes as f64;
        acc - (probability * probability.log2()) // Shannon entropy formula
    });

    Ok(entropy)
}

//return a vector of 8-bit color values based on the file content
pub fn color_based_hex(file_path: String) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut file = File::open(file_path)?;
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer)?;
    let color_squares: Vec<u8> = buffer.iter().map(|&byte| byte % 255).collect();

    Ok(color_squares)
}

pub fn main() -> io::Result<()> {
    let args: Vec<String> = env::args().collect();
    if args.len() < 3 {
        eprintln!("Usage: cargo run -- <view/edit/random/pe-header/elf-functions/entropy/strings> <file_path> [<offset> <new_value>]");
        process::exit(1);
    }

    let mode = &args[1];
    let file_path = &args[2];

    let mut content = fs::read(file_path)?;
    save_hash(&content)?;

    match mode.as_str() {
        "view" => {
            let file_content = view_file(file_path).unwrap_or_else(|e| {
                eprintln!("Error reading file: {}", e);
                std::process::exit(1);
            });
            println!("{}", file_content);
        }
        "random" => random_edit(&mut content)?,

        "pe-header" => {
            let header_info = parse_pe_header(file_path);
            println!("{:?}", header_info);
            process::exit(1);
        }
        "elf-functions" => {
            let functions = extract_function_names_from_elf(&content);
            println!("{:?}", functions);
            process::exit(1);
        }
        "entropy" => {
            let entropy_results = calculate_entropy_by_offset(&content, 256); // Example window size
            for (offset, entropy) in entropy_results {
                println!("Offset: 0x{:x}, Entropy: {:.2}", offset, entropy);
            }
            process::exit(1);
        }
        "edit" => {
            if args.len() == 5 {
                let offset = usize::from_str_radix(&args[3], 16).unwrap_or_else(|_| {
                    eprintln!("Invalid offset.");
                    process::exit(1);
                });
                let new_value = u8::from_str_radix(&args[4], 16).unwrap_or_else(|_| {
                    eprintln!("Invalid new value.");
                    process::exit(1);
                });
                edit_file(&mut content, offset, new_value)?;
            }
        }
        "strings" => {
            let strings = extract_strings(file_path).unwrap_or_else(|e| {
                eprintln!("Error extracting strings: {}", e);
                process::exit(1);
            });
            for string in strings {
                println!("{}", string);
            }
        }
        _ => {
            eprintln!("Invalid mode. Use 'view', 'edit', 'random', 'pe-header', 'elf-functions', or 'entropy'.");
            process::exit(1);
        }
    }

    Ok(())
}

pub fn view_file(file_path: &str) -> io::Result<String> {
    let mut file = fs::File::open(file_path)?;
    let mut contents = Vec::new();
    file.read_to_end(&mut contents)?;

    let mut result = String::new();
    for (index, byte) in contents.iter().enumerate() {
        if index % 16 == 0 {
            if index != 0 {
                // Append ASCII representation for the previous line before starting a new line
                result += " |";
                let start = if index < 16 { 0 } else { index - 16 };
                let end = index;
                let text = contents[start..end]
                    .iter()
                    .map(|&c| if c >= 32 && c <= 126 { c as char } else { '.' })
                    .collect::<String>();
                result += &text;
                result += "|\n";
            }
            result += &format!("{:08x}: ", index);
        }
        result += &format!("{:02x} ", byte);
    }

    // Handle the ASCII preview for the last line if the file size isn't a multiple of 16
    if !contents.is_empty() {
        let padding = 16 - (contents.len() % 16);
        for _ in 0..padding {
            result += "   "; // Padding for the hex view
        }
        result += " |";
        let start = contents.len() - (contents.len() % 16);
        let text = contents[start..]
            .iter()
            .map(|&c| if c >= 32 && c <= 126 { c as char } else { '.' })
            .collect::<String>();
        result += &text;
        result += "|";
    }

    Ok(result)
}

pub fn edit_file(content: &mut Vec<u8>, offset: usize, new_value: u8) -> io::Result<()> {
    if offset < content.len() {
        content[offset] = new_value;
        println!(
            "Byte at offset {:x} has been changed to {:02x}.",
            offset, new_value
        );
    } else {
        eprintln!("Offset {:x} is out of bounds.", offset);
    }
    Ok(())
}

pub fn random_edit(content: &mut Vec<u8>) -> io::Result<()> {
    let mut rng = thread_rng();
    let positions: Vec<usize> = content
        .iter()
        .enumerate()
        .filter(|&(_, &value)| value == 0x00)
        .map(|(i, _)| i)
        .collect();

    if let Some(&pos) = positions.choose(&mut rng) {
        let random_value: u8 = rng.gen();
        content[pos] = random_value;
        println!(
            "Byte at random zero position {:x} has been changed to {:02x}.",
            pos, random_value
        );
    } else {
        println!("No zero bytes to replace.");
    }

    Ok(())
}

pub fn save_hash(content: &[u8]) -> io::Result<()> {
    let mut hasher = Sha256::new();
    hasher.update(content);
    let hash = hasher.finalize();
    let hash_str = format!("{:x}", hash);
    println!("SHA256: {}", hash_str);
    let first_64_bits = &hash_str[..16];
    let name = format!("{}.txt", first_64_bits);
    print!("Saving hash to file {}... ", name);
    fs::write(name, hash_str)?;
    Ok(())
}

pub fn extract_detail_exe(
    file_path: &String,
) -> Result<HashMap<String, String>, Box<dyn std::error::Error>> {
    let mut file = File::open(file_path)?;
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer)?;

    let mut details = HashMap::new();

    match PE::parse(&buffer) {
        Ok(pe) => {
            details.insert("Entry Point".to_string(), format!("0x{:x}", pe.entry));

            // COFF Header details
            details.insert(
                "Machine".to_string(),
                format!("0x{:x}", pe.header.coff_header.machine),
            );
            details.insert(
                "Number of Sections".to_string(),
                pe.header.coff_header.number_of_sections.to_string(),
            );
            details.insert(
                "Time Date Stamp".to_string(),
                pe.header.coff_header.time_date_stamp.to_string(),
            );
            details.insert(
                "Pointer to Symbol Table".to_string(),
                pe.header.coff_header.pointer_to_symbol_table.to_string(),
            );
            details.insert(
                "Number of Sections".to_string(),
                pe.header.coff_header.number_of_sections.to_string(),
            );
            details.insert(
                "Size of Optional Header".to_string(),
                pe.header.coff_header.size_of_optional_header.to_string(),
            );
            details.insert(
                "Characteristics".to_string(),
                format!("0x{:x}", pe.header.coff_header.characteristics),
            );

            // Section Headers
            for (index, section) in pe.sections.iter().enumerate() {
                let section_name = format!("Section {} Name", index + 1);
                let section_detail = format!(
                    "Virtual Size: 0x{:x}, Virtual Address: 0x{:x}",
                    section.virtual_size, section.virtual_address
                );
                details.insert(section_name, section_detail);
            }

            // Imports
            for (index, import) in pe.imports.iter().enumerate() {
                let import_name = format!("Import {} Name", index + 1);
                let import_fields = format!(
                    "DLL: {}, Ordinal: {}, Offset: {}, RVA: 0x{:x}, Size: {}",
                    import.dll, import.ordinal, import.offset, import.rva, import.size
                );
                details.insert(import_name, import_fields);
            }
            // Exports
            for (index, export) in pe.exports.iter().enumerate() {
                if let Some(name) = &export.name {
                    let export_name = format!("Export {} Name", index + 1);
                    let export_detail = format!("Name: {}, Address: 0x{:x}", name, export.rva);
                    details.insert(export_name, export_detail);
                }
            }
        }
        Err(err) => return Err(Box::new(err)),
    }

    Ok(details)
}

pub fn parse_pe_header(file_path: &str) -> Result<goblin::pe::header::Header, Box<dyn Error>> {
    // Open the file at the given path
    let mut file = File::open(file_path)?;

    // Read the file's contents into a buffer
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer)?;

    // Parse the buffer as a PE file
    let pe = PE::parse(&buffer)?;

    // Return the PE header
    Ok(pe.header)
}
#[allow(deprecated)]
pub fn extract_function_names_from_elf(bytes: &[u8]) -> Result<Vec<String>, goblin::error::Error> {
    let elf = Elf::parse(bytes)?;
    let mut function_names = Vec::new();
    for sym in elf.syms.iter() {
        if let Some(Ok(name)) = elf
            .strtab
            .get(sym.st_name)
            .map(|res| res.map(|s| s.to_string()))
        {
            function_names.push(name);
        }
    }
    Ok(function_names)
}

pub fn calculate_entropy_by_offset(data: &[u8], window_size: usize) -> Vec<(usize, f64)> {
    let mut results = Vec::new();
    let mut offset = 0;

    while offset + window_size <= data.len() {
        let window = &data[offset..offset + window_size];
        let entropy = calculate_entropy_byte(window);
        results.push((offset, entropy));
        offset += window_size;
    }

    results
}

pub fn calculate_entropy_byte(data: &[u8]) -> f64 {
    let mut frequency = HashMap::new();

    for &byte in data {
        *frequency.entry(byte).or_insert(0) += 1;
    }

    let len = data.len() as f64;
    frequency.values().fold(0.0, |acc, &count| {
        let probability = count as f64 / len;
        acc - (probability * probability.log2())
    })
}

pub fn extract_strings(file_path: &str) -> Result<Vec<String>, Box<dyn Error>> {
    let mut file = File::open(file_path)?;
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer)?;

    let obj = Object::parse(&buffer)?;
    let strings = match obj {
        Object::PE(pe) => extract_strings_from_pe_sections(&pe.sections, &buffer),
        Object::Elf(elf) => Ok(extract_strings_from_elf_sections(
            &elf.section_headers,
            &buffer,
        )),
        _ => Err("Unsupported format".into()),
    }?;

    Ok(strings)
}

fn extract_strings_from_pe_sections(
    sections: &[goblin::pe::section_table::SectionTable],
    buffer: &[u8],
) -> Result<Vec<String>, Box<dyn Error>> {
    let mut strings = Vec::new();
    for section in sections {
        let start = section.pointer_to_raw_data as usize;
        let end = start + section.size_of_raw_data as usize;

        if start < buffer.len() && end <= buffer.len() {
            let section_data = &buffer[start..end];

            let mut current_string = Vec::new();
            for &byte in section_data {
                if byte.is_ascii_graphic() || byte == b' ' {
                    current_string.push(byte);
                } else if byte == 0 && !current_string.is_empty() {
                    if current_string.len() > 4 {
                        if let Ok(string) = String::from_utf8(current_string.clone()) {
                            strings.push(string);
                        }
                    }
                    current_string.clear();
                }
            }
        }
    }

    Ok(strings)
}

fn extract_strings_from_elf_sections(
    headers: &[goblin::elf::section_header::SectionHeader],
    buffer: &[u8],
) -> Vec<String> {
    let mut strings = Vec::new();

    for header in headers {
        let start = header.sh_offset as usize;
        let end = start + header.sh_size as usize;
        let section_data = &buffer[start..end];

        let mut current_string = Vec::new();
        for &byte in section_data {
            if byte.is_ascii_graphic() || byte == b' ' {
                current_string.push(byte);
            } else if byte == 0 && !current_string.is_empty() {
                if current_string.len() > 4 {
                    if let Ok(string) = String::from_utf8(current_string.clone()) {
                        strings.push(string);
                    }
                }
                current_string.clear();
            }
        }
    }
    strings
}
