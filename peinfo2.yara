import "pe"
import "console"
import "hash"
import "magic"
import "math"

// File scanning, YARA >= 4.2 with pe, console, hash, magic and math.
// Logging only: final false intentionally prevents a rule match.
// Optional legacy fields must not stop the AND chain when undefined.

rule EntryPointHashLog
{
    condition:
	pe.is_pe and
	
	(console.log("FromBegin: ", pe.entry_point) or true) and 
	(console.log("FromEnd: ", filesize-pe.entry_point) or true) and 
	(console.log("EntryHash10: ", hash.sha256(pe.entry_point,10)) or true) and 
	(console.log("EntryHash20: ", hash.sha256(pe.entry_point,20)) or true) and 
	(console.log("EntryHash30: ", hash.sha256(pe.entry_point,30)) or true) and 
	(console.log("EntryHash40: ", hash.sha256(pe.entry_point,40)) or true) and 
	(console.log("EntryHash50: ", hash.sha256(pe.entry_point,50)) or true) and 
	(console.log("EntryHash60: ", hash.sha256(pe.entry_point,60)) or true) and 
	(console.log("EntryHash70: ", hash.sha256(pe.entry_point,70)) or true) and 
	(console.log("EntryHash80: ", hash.sha256(pe.entry_point,80)) or true) and 
        (console.log("InitializedData: ", pe.size_of_initialized_data) or true) and
        (console.log("Characteristics: ", pe.characteristics) or true) and
	(console.log("RELOCS_STRIPPED: ", (pe.characteristics & pe.RELOCS_STRIPPED)) or true) and
	(console.log("LINE_NUMS_STRIPPED: ", (pe.characteristics & pe.LINE_NUMS_STRIPPED)) or true) and
	(console.log("LOCAL_SYMS_STRIPPED: ", (pe.characteristics & pe.LOCAL_SYMS_STRIPPED)) or true) and
	(console.log("LARGE_ADDRESS_AWARE: ", (pe.characteristics & pe.LARGE_ADDRESS_AWARE)) or true) and
	(console.log("Number of imported functions: ", pe.number_of_imported_functions) or true) and

        (console.log("EntryPoint: ", pe.entry_point) or true) and
        (console.log("InitializedData: ", pe.size_of_initialized_data) or true) and
        (console.log("Size of stack reserve: ", pe.size_of_stack_reserve) or true) and
        (console.log("Size of heap reserve: ", pe.size_of_heap_reserve) or true) and
        (console.log("Number of signatures: ", pe.number_of_signatures) or true) and
        (console.log("Machine: ", pe.machine) or true) and
        (console.log("Subsystem: ", pe.subsystem) or true) and
	(console.log("Type: ", pe.overlay.offset) or true) and
	(console.log("Type: ", magic.type()) or true) and
	(console.log("MimeType: ", magic.mime_type()) or true) and
	(console.log("Imphash: ", pe.imphash()) or true) and
	(console.log("Cheksum: ", pe.checksum) or true) and
	(console.log("CalculatedChecksum: ", pe.calculate_checksum()) or true) and
	(console.log("Timestamp: ", pe.timestamp) or true)and
	(console.log("SizeOfCode: ", pe.size_of_code) or true)and
	(console.log("NumberOfResources: ", pe.number_of_resources) or true)and
	(console.log("Pe machine: ", pe.machine) or true) and

	(console.log("OS major version: ",pe.os_version.major) or true) and

        (console.log("OS minor version: ",pe.os_version.minor) or true) and

	(for all signature in pe.signatures : 
	( 
		(console.log("Signature: ", signature.subject) or true) and
		(console.log("thumbprint: ", signature.thumbprint) or true) and
		(console.log("version: ", signature.version) or true) and
		(console.log("Issuer: ", signature.issuer) or true) and
		(console.log("Algorithm: ", signature.algorithm) or true) and
                (console.log("Serial: ",signature.serial) or true)
	) or true) and
	(for all sect in pe.sections : 
	(
		(console.log("SectionName: ", sect.name) or true) and
		(console.log("SectionFullName: ", sect.full_name) or true) and
		(console.log("SectionVADDR: ", sect.virtual_address) or true) and 
		(console.log("SectionVSIZE: ", sect.virtual_size) or true) and 
                (console.log("SectionCharacteristics: ",sect.characteristics) or true) and
                (console.log("SectionRawOffset: ",sect.raw_data_offset) or true) and
                (console.log("SectionRawSize: ",sect.raw_data_size) or true) and
                (console.log("NumberOfLineNumbers: ",sect.number_of_line_numbers) or true)

	) or true)  and
        // Additional family-comparison features. Exact hashes identify identical bytes, not a family.
        (console.log("FileSize: ", filesize) or console.log("FileSize: N/A")) and
        (console.log("FileSHA256: ", hash.sha256(0, filesize)) or console.log("FileSHA256: N/A")) and
        (console.log("FileEntropy: ", math.entropy(0, filesize)) or console.log("FileEntropy: N/A")) and
        (console.log("OptionalHeaderMagic: ", pe.opthdr_magic) or console.log("OptionalHeaderMagic: N/A")) and
        (console.log("NumberOfSections: ", pe.number_of_sections) or console.log("NumberOfSections: N/A")) and
        (console.log("EntryPointRVA: ", pe.entry_point_raw) or console.log("EntryPointRVA: N/A")) and
        (console.log("ImageBase: ", pe.image_base) or console.log("ImageBase: N/A")) and
        (console.log("SizeOfImage: ", pe.size_of_image) or console.log("SizeOfImage: N/A")) and
        (console.log("SizeOfHeaders: ", pe.size_of_headers) or console.log("SizeOfHeaders: N/A")) and
        (console.log("UninitializedData: ", pe.size_of_uninitialized_data) or console.log("UninitializedData: N/A")) and
        (console.log("SectionAlignment: ", pe.section_alignment) or console.log("SectionAlignment: N/A")) and
        (console.log("FileAlignment: ", pe.file_alignment) or console.log("FileAlignment: N/A")) and
        (console.log("DllCharacteristics: ", pe.dll_characteristics) or console.log("DllCharacteristics: N/A")) and
        (console.log("LinkerMajor: ", pe.linker_version.major) or console.log("LinkerMajor: N/A")) and
        (console.log("LinkerMinor: ", pe.linker_version.minor) or console.log("LinkerMinor: N/A")) and
        (console.log("ImageVersionMajor: ", pe.image_version.major) or console.log("ImageVersionMajor: N/A")) and
        (console.log("ImageVersionMinor: ", pe.image_version.minor) or console.log("ImageVersionMinor: N/A")) and
        (console.log("SubsystemVersionMajor: ", pe.subsystem_version.major) or console.log("SubsystemVersionMajor: N/A")) and
        (console.log("SubsystemVersionMinor: ", pe.subsystem_version.minor) or console.log("SubsystemVersionMinor: N/A")) and
        (console.log("StackCommit: ", pe.size_of_stack_commit) or console.log("StackCommit: N/A")) and
        (console.log("HeapCommit: ", pe.size_of_heap_commit) or console.log("HeapCommit: N/A")) and

        // Build metadata: missing fields are N/A; metadata can be forged.
        (console.log("PDBPath: ", pe.pdb_path) or console.log("PDBPath: N/A")) and
        (console.log("RichHeaderLength: ", pe.rich_signature.length) or console.log("RichHeaderLength: N/A")) and
        (console.log("RichClearSHA256: ", hash.sha256(pe.rich_signature.clear_data)) or console.log("RichClearSHA256: N/A")) and
        (for all key, value in pe.version_info : (
            console.log("VersionKey: ", key) and console.log("VersionValue: ", value)
        ) or true) and

        // Imports/exports: keep DLL context and ordinal-only imports.
        (console.log("ImportedDLLCount: ", pe.number_of_imports) or console.log("ImportedDLLCount: N/A")) and
        (console.log("DelayedDLLCount: ", pe.number_of_delayed_imports) or console.log("DelayedDLLCount: N/A")) and
        (console.log("DelayedFunctionCount: ", pe.number_of_delayed_imported_functions) or console.log("DelayedFunctionCount: N/A")) and
        (console.log("ExportCount: ", pe.number_of_exports) or console.log("ExportCount: N/A")) and
        (console.log("ExportDLLName: ", pe.dll_name) or console.log("ExportDLLName: N/A")) and
        (console.log("ExportTimestamp: ", pe.export_timestamp) or console.log("ExportTimestamp: N/A")) and
        (for all lib in pe.import_details : (
            (console.log("ImportDLL: ", lib.library_name) or console.log("ImportDLL: N/A")) and
            (console.log("ImportFunctionCount: ", lib.number_of_functions) or console.log("ImportFunctionCount: N/A")) and
            (for all fn in lib.functions : (
                (console.log("ImportName: ", fn.name) or console.log("ImportName: N/A")) and
                (console.log("ImportOrdinal: ", fn.ordinal) or console.log("ImportOrdinal: N/A"))
            ) or true)
        ) or true) and
        (for all lib in pe.delayed_import_details : (
            (console.log("DelayImportDLL: ", lib.library_name) or console.log("DelayImportDLL: N/A")) and
            (console.log("DelayImportFunctionCount: ", lib.number_of_functions) or console.log("DelayImportFunctionCount: N/A")) and
            (for all fn in lib.functions : (
                (console.log("DelayImportName: ", fn.name) or console.log("DelayImportName: N/A")) and
                (console.log("DelayImportOrdinal: ", fn.ordinal) or console.log("DelayImportOrdinal: N/A"))
            ) or true)
        ) or true) and
        (for all exp in pe.export_details : (
            (console.log("ExportName: ", exp.name) or console.log("ExportName: N/A")) and
            (console.log("ExportOrdinal: ", exp.ordinal) or console.log("ExportOrdinal: N/A")) and
            (console.log("ExportForwardName: ", exp.forward_name) or console.log("ExportForwardName: N/A")) and
            (console.log("ExportOffset: ", exp.offset) or console.log("ExportOffset: N/A"))
        ) or true) and

        // Data directories: indices follow IMAGE_DIRECTORY_ENTRY_*; security uses file offset.
        (for all i in (0..15) : (
            console.log("DirectoryIndex: ", i) and
            (console.log("DirectoryAddress: ", pe.data_directories[i].virtual_address) or console.log("DirectoryAddress: N/A")) and
            (console.log("DirectorySize: ", pe.data_directories[i].size) or console.log("DirectorySize: N/A"))
        ) or true) and

        // Section content and entry point location (raw file offsets).
        (for all sect in pe.sections : (
            (console.log("FeatureSectionName: ", sect.name) or console.log("FeatureSectionName: N/A")) and
            (console.log("SectionExecutableMask: ", sect.characteristics & pe.SECTION_MEM_EXECUTE) or console.log("SectionExecutableMask: N/A")) and
            (console.log("SectionWritableMask: ", sect.characteristics & pe.SECTION_MEM_WRITE) or console.log("SectionWritableMask: N/A")) and
            (console.log("SectionVirtualMinusRaw: ", sect.virtual_size - sect.raw_data_size) or console.log("SectionVirtualMinusRaw: N/A")) and
            (console.log("SectionRelocationCount: ", sect.number_of_relocations) or console.log("SectionRelocationCount: N/A")) and
            (((sect.raw_data_size > 0 and sect.raw_data_offset >= 0 and sect.raw_data_offset <= filesize and sect.raw_data_size <= filesize - sect.raw_data_offset) and
                (console.log("SectionEntropy: ", math.entropy(sect.raw_data_offset, sect.raw_data_size)) or console.log("SectionEntropy: N/A")) and
                (console.log("SectionSHA256: ", hash.sha256(sect.raw_data_offset, sect.raw_data_size)) or console.log("SectionSHA256: N/A"))) or console.log("SectionData: empty or invalid range")) and
            ((pe.entry_point >= sect.raw_data_offset and pe.entry_point - sect.raw_data_offset < sect.raw_data_size and
                console.log("EntryPointSection: ", sect.name) and
                console.log("EntryPointOffsetInSection: ", pe.entry_point - sect.raw_data_offset)) or true)
        ) or true) and

        // Overlay may include legitimate installer data or certificates.
        (console.log("OverlayOffset: ", pe.overlay.offset) or console.log("OverlayOffset: N/A")) and
        (console.log("OverlaySize: ", pe.overlay.size) or console.log("OverlaySize: N/A")) and
        (((pe.overlay.size > 0 and pe.overlay.offset >= 0 and pe.overlay.offset <= filesize and pe.overlay.size <= filesize - pe.overlay.offset) and
            (console.log("OverlayEntropy: ", math.entropy(pe.overlay.offset, pe.overlay.size)) or console.log("OverlayEntropy: N/A")) and
            (console.log("OverlaySHA256: ", hash.sha256(pe.overlay.offset, pe.overlay.size)) or console.log("OverlaySHA256: N/A"))) or console.log("OverlayData: absent or invalid range")) and

        // Resource hashes include icons, manifests and embedded payloads.
        (console.log("ResourceTimestamp: ", pe.resource_timestamp) or console.log("ResourceTimestamp: N/A")) and
        (for all res in pe.resources : (
            (console.log("ResourceType: ", res.type) or console.log("ResourceType: N/A")) and
            (console.log("ResourceID: ", res.id) or console.log("ResourceID: N/A")) and
            (console.log("ResourceLanguage: ", res.language) or console.log("ResourceLanguage: N/A")) and
            (console.log("ResourceTypeString: ", res.type_string) or console.log("ResourceTypeString: N/A")) and
            (console.log("ResourceNameString: ", res.name_string) or console.log("ResourceNameString: N/A")) and
            (console.log("ResourceLanguageString: ", res.language_string) or console.log("ResourceLanguageString: N/A")) and
            (console.log("ResourceRVA: ", res.rva) or console.log("ResourceRVA: N/A")) and
            (console.log("ResourceOffset: ", res.offset) or console.log("ResourceOffset: N/A")) and
            (console.log("ResourceLength: ", res.length) or console.log("ResourceLength: N/A")) and
            (((res.length > 0 and res.offset >= 0 and res.offset <= filesize and res.length <= filesize - res.offset) and
                (console.log("ResourceEntropy: ", math.entropy(res.offset, res.length)) or console.log("ResourceEntropy: N/A")) and
                (console.log("ResourceSHA256: ", hash.sha256(res.offset, res.length)) or console.log("ResourceSHA256: N/A"))) or console.log("ResourceData: empty or invalid range"))
        ) or true) and

        console.log("ExtendedPEInfo: END") and
    false
}