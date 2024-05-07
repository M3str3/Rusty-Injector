use std::io::{self, Read, BufReader};
use std::path::Path;
use std::fs::File;

// Verifica si un path dado corresponde a un archivo existente.
fn _is_file(path: &str) -> bool {
    Path::new(path).is_file()
}

// Lee el contenido de un archivo y determina el formato del shellcode para parsearlo.
fn _read_shellcode_from_file<P: AsRef<Path>>(path: P) -> io::Result<Vec<u8>> {
    let file = File::open(path)?;
    let mut reader = BufReader::new(file);
    let mut contents = String::new();
    reader.read_to_string(&mut contents)?;

    if contents.starts_with("const SHELLCODE") {
        Ok(_parse_rust_style_shellcode(&contents))
    } else if contents.contains("\\x") {
        Ok(_parse_c_style_shellcode(&contents))
    } else {
        println!("[!] Assuming plain hex style for shellcode arg");
        Ok(_parse_plain_hex(&contents))
    }
}

// Parsea shellcode en formato Rust.
fn _parse_rust_style_shellcode(contents: &str) -> Vec<u8> {
    contents
        .split("= [").last().unwrap_or_default() // Asume que la shellcode está después de '= ['
        .split(']').next().unwrap_or_default() // Asume que termina con ']'
        .split(',')
        .filter_map(|s| s.trim().strip_prefix("0x"))
        .filter_map(|s| u8::from_str_radix(s, 16).ok())
        .collect()
}

// Parsea shellcode en formato C.
fn _parse_c_style_shellcode(contents: &str) -> Vec<u8> {
    contents
        .split("\\x")
        .filter_map(|part| if !part.is_empty() { u8::from_str_radix(part, 16).ok() } else { None })
        .collect()
}

// Convierte una cadena hexadecimal en un vector de bytes.
fn _parse_plain_hex(hex_str: &str) -> Vec<u8> {
    hex_str
        .chars()
        .filter(|c| !c.is_whitespace()) // Elimina los espacios y saltos de línea
        .collect::<String>()
        .as_bytes()
        .chunks(2)
        .filter_map(|chunk| std::str::from_utf8(chunk).ok())
        .filter_map(|hex_digit| u8::from_str_radix(hex_digit, 16).ok())
        .collect()
}

pub fn _read_shellcode(arg: &str) -> io::Result<Vec<u8>> {
    if _is_file(arg) {
        _read_shellcode_from_file(arg)
    } else {
        _read_shellcode_from_arg(arg)
    }
}

// Lee shellcode directamente de un argumento si no es un archivo.
fn _read_shellcode_from_arg(shellcode_text: &str) -> io::Result<Vec<u8>> {
    Ok(_parse_plain_hex(shellcode_text))
}

