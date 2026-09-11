/*
 * feature_extractor.yar
 * -----------------------------------------------------------------------
 * Tanari specifikacio szerinti valtozat: a "console" YARA modul console.log
 * hivasait hasznaljuk kulcs-ertek parok kiirasara, amiket az extract_features.py
 * egy console_callback fuggvennyel kap el es alakit dataset sorra.
 *
 * FONTOS KORLATOK (dokumentalva, mert befolyasoljak a Python-oldali logikat):
 *
 * 1) A "magic" modul (import "magic") NEM resze a szabvanyos pip yara-python
 *    csomagnak sem Windowson, sem tipikusan Linux/Debianon - kulon libmagic-cal
 *    forditott build kell hozza. Ha nincs jelen, ennek a fajlnak a forditasa
 *    ELSZALL ("unknown module magic"), ami a TELJES szabalykeszletet
 *    hasznalhatatlanna teszi. Ezert az extract_features.py eloszor ezt a
 *    fajlt probalja leforditani, es HA NEM SIKERUL, automatikusan a
 *    feature_extractor_no_magic.yar tartalek valtozatra valt (magic import
 *    es a Type_magic sor nelkul), a Type_magic mezot pedig Python oldalon,
 *    a pefile OPTIONAL_HEADER.Magic ertekebol potolja (PE32 / PE32+ / ROM).
 *
 * 2) A condition egyetlen nagy AND-lanc: ha barmelyik korabbi tag (pl. egy
 *    hash.sha256 hivas egy serult/csomagolt fajl anomalis entry_point-jan)
 *    undefined erteket ad, a YARA rovidzar-kiertekeles miatt a lanc UTANI
 *    console.log hivasok NEM futnak le -> reszleges/ures log-kimenet
 *    keletkezhet serult mintaknal. Ezt szandekosan, szo szerint a kapott
 *    specifikacio szerint hagytuk meg (nem irtuk at try/except-es kulon
 *    console.log hivasokra), a hianyzo mezoket a Python oldal potolja
 *    NaN/None ertekkel es jelzi a "partial_console_log" oszlopban.
 * -----------------------------------------------------------------------
 */

import "pe"
import "console"
import "hash"
import "magic"

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
        console.log("Type_overlay: ", pe.overlay.offset) and
        console.log("Type_magic: ", magic.type())
}
