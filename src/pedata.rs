use goblin::pe::PE;

pub const E_LFANEW_OFFSET:usize = 0x3C;


/// Get the offset of the IMAGE NT HEADERS
/// Arguments:
///     -   buffer: The buffer to search
pub fn _get_image_nt_header_offset( buffer: &Vec<u8>) -> u32{
    if buffer.len() < E_LFANEW_OFFSET + 4 {
        panic!("[!] [ERROR]: Buffer too small to contain an NT header offset");
    }

    let offset = &buffer[E_LFANEW_OFFSET..E_LFANEW_OFFSET + 4];
    u32::from_le_bytes(offset.try_into().expect("Failed to convert bytes to u32"))
}

/// Get the offset of the IMAGE NT HEADERS
/// Arguments:
///     -   buffer: The buffer to search image nt header offset
///     -   pe: The PE struct from goblin to get the offset
pub fn _get_section_table_offset( buffer: &Vec<u8>, pe: &PE<'_> ) -> u32 {
    let optional_header_offset:u32 = _get_image_nt_header_offset(&buffer) + 4 + 20; // Saltar 4 bytes de 'Signature' + 20 bytes de 'IMAGE_FILE_HEADER'
    let size_of_optional_header:u32 = pe.header.coff_header.size_of_optional_header as u32;
    return optional_header_offset + size_of_optional_header;
}

/// Retrieves the actual entry point address from a PE file, not just the relative virtual address (RVA).
/// Arguments:
///     - pe: A PE file handle provided by Goblin.
/// Returns:
///     - The actual entry point address as u32.
fn _get_real_entry_point(pe: PE<'_>) -> u32 {
    println!("[*] Getting real entry point ( not rva ) ....");

    // Leer el punto de entrada del archivo PE
    let entry_point_rva: u32 = pe
        .header
        .optional_header
        .unwrap()
        .standard_fields
        .address_of_entry_point as u32;
    if let Some(section) = pe.sections.iter().find(|section| {
        entry_point_rva >= section.virtual_address
            && entry_point_rva < section.virtual_address + section.virtual_size
    }) {
        let entry_point_offset =
            (entry_point_rva - section.virtual_address) + section.pointer_to_raw_data as u32;
        println!("[*] Real entry point 0x{:X}", entry_point_offset);
        return entry_point_offset;
    }
    0
}

/// Modifies the entry point address within the PE file buffer.
/// Arguments:
///     - new_entry_point: The new entry point address to set.
///     - buffer: The buffer representing the PE file to modify.
pub fn change_entry_point(new_entry_point: u32, buffer: &mut Vec<u8>) {
    // Calcula la posicion de la orden del punto de entrada
    let e_lfanew = u32::from_le_bytes(
        buffer[E_LFANEW_OFFSET..E_LFANEW_OFFSET + 4]
            .try_into()
            .unwrap(),
    );
    let entry_point_offset = e_lfanew + 4 + 20 + 0x10;

    println!("[*] Changing entry point to 0x{:X}", new_entry_point);

    println!("[*] Entry point on position {:X}", entry_point_offset);
    // Modificar el punto de entrada
    buffer[entry_point_offset as usize..entry_point_offset as usize + 4]
        .copy_from_slice(&new_entry_point.to_le_bytes());

    println!("[*] Entry point changed");
}

/// Finds the first section within the PE file.
/// Arguments:
///     - pe: A reference to the PE struct.
/// Returns:
///     - An option containing a reference to the first section if found.
pub fn _find_first_section<'a>(pe: &'a PE<'a>) -> Option<&'a goblin::pe::section_table::SectionTable> {
    pe.sections
        .iter()
        .min_by_key(|section| section.pointer_to_raw_data)
}

/// Finds the last section within the PE file.
/// Arguments:
///     - pe: A reference to the PE struct.
/// Returns:
///     - An option containing a reference to the last section if found.
pub fn find_last_section<'a>(pe: &'a PE<'a>) -> Option<&'a goblin::pe::section_table::SectionTable> {
    pe.sections
        .iter()
        .max_by_key(|section| section.pointer_to_raw_data)
}


/// Calculate padding
pub fn calculate_padding(current_length: usize, alignment: u32) -> usize {
    let alignment:usize = alignment as usize;
    (alignment - (current_length % alignment)) % alignment
}
