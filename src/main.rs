use reverse_engineering_lib::parse_pe_header;

fn main() {
    let file_path = "C:\\Windows\\System32\\notepad.exe";
    let pe_header = parse_pe_header(file_path).unwrap();
    println!("{:?}", pe_header);
}
