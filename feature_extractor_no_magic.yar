/*
 * feature_extractor_no_magic.yar
 * -----------------------------------------------------------------------
 * Tartalek valtozata a feature_extractor.yar-nak, "import magic" es a
 * Type_magic console.log sor NELKUL - automatikusan ezt hasznalja az
 * extract_features.py, ha a kornyezetben a yara-python nincs magic
 * modul tamogatassal forditva (lasd feature_extractor.yar fejlec-kommentjet).
 *
 * A Type_magic mezot ilyenkor a Python oldal potolja a pefile konyvtar
 * OPTIONAL_HEADER.Magic ertekebol (PE32 / PE32+ / ROM).
 * -----------------------------------------------------------------------
 */

import "pe"
import "console"
import "hash"

rule EntryPointHashLog
{
    condition:
        pe.is_pe and
        console.log("FromBegin: ", pe.entry_point) and
        console.log("FromEnd: ", filesize - pe.entry_point) and
        console.log("EntryHash10: ", hash.sha256(pe.entry_point, 10)) and
        console.log("EntryHash20: ", hash.sha256(pe.entry_point, 20)) and
        console.log("EntryHash30: ", hash.sha256(pe.entry_point, 30)) and
        console.log("EntryHash40: ", hash.sha256(pe.entry_point, 40)) and
        console.log("EntryHash50: ", hash.sha256(pe.entry_point, 50)) and
        console.log("EntryHash60: ", hash.sha256(pe.entry_point, 60)) and
        console.log("EntryHash70: ", hash.sha256(pe.entry_point, 70)) and
        console.log("EntryHash80: ", hash.sha256(pe.entry_point, 80)) and
        console.log("InitializedData: ", pe.size_of_initialized_data) and
        console.log("RELOCS_STRIPPED: ", (pe.characteristics & pe.RELOCS_STRIPPED)) and
        console.log("LINE_NUMS_STRIPPED: ", (pe.characteristics & pe.LINE_NUMS_STRIPPED)) and
        console.log("LOCAL_SYMS_STRIPPED: ", (pe.characteristics & pe.LOCAL_SYMS_STRIPPED)) and
        console.log("LARGE_ADDRESS_AWARE: ", (pe.characteristics & pe.LARGE_ADDRESS_AWARE)) and
        console.log("Number of imported functions: ", pe.number_of_imported_functions) and
        console.log("EntryPoint: ", pe.entry_point) and
        console.log("Size of stack reserve: ", pe.size_of_stack_reserve) and
        console.log("Size of heap reserve: ", pe.size_of_heap_reserve) and
        console.log("Number of signatures: ", pe.number_of_signatures) and
        console.log("Machine: ", pe.machine) and
        console.log("Subsystem: ", pe.subsystem) and
        console.log("Type_overlay: ", pe.overlay.offset)
}
