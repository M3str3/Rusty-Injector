use goblin::pe::PE;
use std::env;
use std::fs;
use std::fs::File;
use std::io::{self, Write};

mod pedata;
mod peinjector;
mod shellcode;

fn main() -> io::Result<()> {
println!("┌────────────────────────────────────────────────────────────────────────────────────────────────────────────┐");
println!("│    ______ _______ _______ _______ ___ ___      _______ ___ ___ ______ _______ _______ _______ _______      │");
println!(r"│    |   __ \   |   |     __|_     _|   |   |    |     __|   |   |   __ \_     _|    |  |     __|    ___|    │");
println!(r"│    |      <   |   |__     | |   |  \     /     |__     |\     /|      <_|   |_|       |    |  |    ___|    │");
println!("│    |___|__|_______|_______| |___|   |___|      |_______| |___| |___|__|_______|__|____|_______|_______|    │");
println!("│                                                                                                            │");
println!("│                                           RUSTY SYRINGE                                                    │");
println!("└────────────────────────────────────────────────────────────────────────────────────────────────────────────┘");

    let args: Vec<String> = env::args().collect();
    if args.len() < 3 {
        println!("Usage: {} <path_to_binary> <out> <shellcode/path_to_shellcode>", args[0]);
        return Ok(());
    }

    let path = &args[1];
    let mut buffer = fs::read(path).expect("Failed to read file");

    println!("---------------------------------------");
    match PE::parse(&buffer.clone()) {
        Ok(pe) => {
            println!("[*] Successfully parsed PE file.");
            match pe.header.coff_header.machine {
                goblin::pe::header::COFF_MACHINE_X86 => println!("Arquitectura x86"),
                goblin::pe::header::COFF_MACHINE_X86_64 => println!("Arquitectura x64"),
                _ => println!("Otra arquitectura"),
            }
            let mut shellcode_bytes = shellcode::_read_shellcode(&args[3]).unwrap();
            peinjector::inject_shellcode(&mut buffer, &pe, &mut shellcode_bytes);
        }

        Err(error) => {
            println!("[!] Error parsing PE file: {:?}", error);
        }
    }
    println!("---------------------------------------");

    let mut output_file = File::create(format!("out/{}", &args[2]))?;
    output_file.write_all(&buffer)?;

    println!("[*] Modified file changed to out/{}\n", &args[2]);

    Ok(())
}
