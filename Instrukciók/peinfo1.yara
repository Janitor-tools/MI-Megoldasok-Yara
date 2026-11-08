import "pe"
import "console"
import "hash"
import "magic"

rule EntryPointHashLog
{
    condition:
	pe.is_pe and
	
	console.log("FromBegin: ", pe.entry_point) and 
	console.log("FromEnd: ", filesize-pe.entry_point) and 
	console.log("EntryHash10: ", hash.sha256(pe.entry_point,10)) and 
	console.log("EntryHash20: ", hash.sha256(pe.entry_point,20)) and 
	console.log("EntryHash30: ", hash.sha256(pe.entry_point,30)) and 
	console.log("EntryHash40: ", hash.sha256(pe.entry_point,40)) and 
	console.log("EntryHash50: ", hash.sha256(pe.entry_point,50)) and 
	console.log("EntryHash60: ", hash.sha256(pe.entry_point,60)) and 
	console.log("EntryHash70: ", hash.sha256(pe.entry_point,70)) and 
	console.log("EntryHash80: ", hash.sha256(pe.entry_point,80)) and 
        console.log("InitializedData: ", pe.size_of_initialized_data) and
        console.log("Characteristics: ", pe.characteristics) and
	console.log("RELOCS_STRIPPED: ", (pe.characteristics & pe.RELOCS_STRIPPED)) and
	console.log("LINE_NUMS_STRIPPED: ", (pe.characteristics & pe.LINE_NUMS_STRIPPED)) and
	console.log("LOCAL_SYMS_STRIPPED: ", (pe.characteristics & pe.LOCAL_SYMS_STRIPPED)) and
	console.log("LARGE_ADDRESS_AWARE: ", (pe.characteristics & pe.LARGE_ADDRESS_AWARE)) and
	console.log("Number of imported functions: ", pe.number_of_imported_functions) and

        console.log("EntryPoint: ", pe.entry_point) and
        console.log("InitializedData: ", pe.size_of_initialized_data) and
        console.log("Size of stack reserve: ", pe.size_of_stack_reserve) and
        console.log("Size of heap reserve: ", pe.size_of_heap_reserve) and
        console.log("Number of signatures: ", pe.number_of_signatures) and
        console.log("Machine: ", pe.machine) and
        console.log("Subsystem: ", pe.subsystem) and
	console.log("Type: ", pe.overlay.offset) and
	console.log("Type: ", magic.type()) and
	console.log("MimeType: ", magic.mime_type()) and
	console.log("Imphash: ", pe.imphash()) and
	console.log("Cheksum: ", pe.checksum) and
	console.log("CalculatedChecksum: ", pe.calculate_checksum()) and
	console.log("Timestamp: ", pe.timestamp)and
	console.log("SizeOfCode: ", pe.size_of_code)and
	console.log("NumberOfResources: ", pe.number_of_resources)and
	console.log("Pe machine: ", pe.machine) and

	console.log("OS major version: ",pe.os_version.major) and

        console.log("OS minor version: ",pe.os_version.minor) and

	for all signature in pe.signatures : 
	( 
		console.log("Signature: ", signature.subject) and
		console.log("thumbprint: ", signature.thumbprint) and
		console.log("version: ", signature.version) and
		console.log("Issuer: ", signature.issuer) and
		console.log("Algorithm: ", signature.algorithm) and
                console.log("Serial: ",signature.serial)
	) and
	for all sect in pe.sections : 
	(
		console.log("SectionName: ", sect.name) and
		console.log("SectionFullName: ", sect.full_name) and
		console.log("SectionVADDR: ", sect.virtual_address) and 
		console.log("SectionVSIZE: ", sect.virtual_size) and 
                console.log("SectionCharacteristics: ",sect.characteristics) and
                console.log("SectionRawOffset: ",sect.raw_data_offset) and
                console.log("SectionRawSize: ",sect.raw_data_size) and
                console.log("NumberOfLineNumbers: ",sect.number_of_line_numbers)

	)  and
    false
}