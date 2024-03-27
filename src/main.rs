use reverse_engineering_lib::disassemble;

fn main() {
    let file_path = "test_files/elf64_test";
    match disassemble(&file_path) {
        Ok(disassembly) => println!("{}", disassembly),
        Err(e) => eprintln!("Disassembly failed: {}", e),
    }
}
