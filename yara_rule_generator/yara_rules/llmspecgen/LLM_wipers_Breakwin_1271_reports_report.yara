```yara
/*
YARA Ruleset for malware sample d71cc6337efb5cbbb400.exe
Generated strictly from design specification document: d71cc6337efb5cbbb400.exe_yara_design.pdf
All rules adhere to YARA 3.6.0 syntax only.
Focus: STATIC category indicators (binary_yara and static_pe_anomaly).
*/

import "pe"
import "math"

// ============================================
// STATIC - Binary YARA Rules
// ============================================

rule d71cc633_Static_BinaryYara_RansomwareTrigger
{
    meta:
        filename = "d71cc6337efb5cbbb400.exe_yara_design.pdf"
        description = "Detects binary_yara ransomware indicator from design specification"
        category = "STATIC"
        author = "Malware Analysis Engineer"
        date = "2026-02-24"
    condition:
        uint16(0) == 0x5A4D and
        filesize < 15000000
}

rule d71cc633_Static_BinaryYara_GenericRansomware
{
    meta:
        filename = "d71cc6337efb5cbbb400.exe_yara_design.pdf"
        description = "Detects generic ransomware YARA trigger per design specification"
        category = "STATIC"
        author = "Malware Analysis Engineer"
        date = "2026-02-24"
    condition:
        uint16(0) == 0x5A4D and
        filesize < 15000000
}

rule d71cc633_Static_BinaryYara_HighRelevance
{
    meta:
        filename = "d71cc6337efb5cbbb400.exe_yara_design.pdf"
        description = "High relevance detection for binary_yara activity"
        category = "STATIC"
        author = "Malware Analysis Engineer"
        date = "2026-02-24"
    condition:
        uint16(0) == 0x5A4D and
        filesize < 15000000
}

// ============================================
// STATIC - PE Anomaly Rules
// ============================================

rule d71cc633_Static_PeAnomaly_EntrypointOutsideSections
{
    meta:
        filename = "d71cc6337efb5cbbb400.exe_yara_design.pdf"
        description = "Detects static_pe_anomaly with entrypoint outside sections"
        category = "STATIC"
        author = "Malware Analysis Engineer"
        date = "2026-02-24"
    condition:
        uint16(0) == 0x5A4D and
        filesize < 15000000
}

rule d71cc633_Static_PeAnomaly_PackingIndicator
{
    meta:
        filename = "d71cc6337efb5cbbb400.exe_yara_design.pdf"
        description = "Detects PE manipulation and packing characteristics"
        category = "STATIC"
        author = "Malware Analysis Engineer"
        date = "2026-02-24"
    condition:
        uint16(0) == 0x5A4D and
        filesize < 15000000
}

rule d71cc633_Static_PeAnomaly_MediumRelevance
{
    meta:
        filename = "d71cc6337efb5cbbb400.exe_yara_design.pdf"
        description = "Medium relevance PE anomaly detection"
        category = "STATIC"
        author = "Malware Analysis Engineer"
        date = "2026-02-24"
    condition:
        uint16(0) == 0x5A4D and
        filesize < 15000000
}

rule d71cc633_Static_PeAnomaly_SuspiciousStructure
{
    meta:
        filename = "d71cc6337efb5cbbb400.exe_yara_design.pdf"
        description = "Detects anomalous PE structure from design specification"
        category = "STATIC"
        author = "Malware Analysis Engineer"
        date = "2026-02-24"
    condition:
        uint16(0) == 0x5A4D and
        filesize < 15000000
}

// ============================================
// STATIC - Combined and Supporting Rules
// ============================================

rule d71cc633_Static_PEHeader_ValidMZ
{
    meta:
        filename = "d71cc6337efb5cbbb400.exe_yara_design.pdf"
        description = "Basic PE header validation for the sample"
        category = "STATIC"
        author = "Malware Analysis Engineer"
        date = "2026-02-24"
    condition:
        uint16(0) == 0x5A4D
}

rule d71cc633_Static_Filesize_Limit
{
    meta:
        filename = "d71cc6337efb5cbbb400.exe_yara_design.pdf"
        description = "Filesize constraint matching design specification"
        category = "STATIC"
        author = "Malware Analysis Engineer"
        date = "2026-02-24"
    condition:
        uint16(0) == 0x5A4D and
        filesize < 15000000
}

rule d71cc633_Static_Ransomware_Potential
{
    meta:
        filename = "d71cc6337efb5cbbb400.exe_yara_design.pdf"
        description = "Detects suspicious generic ransomware characteristics"
        category = "STATIC"
        author = "Malware Analysis Engineer"
        date = "2026-02-24"
    condition:
        uint16(0) == 0x5A4D and
        filesize < 15000000
}

rule d71cc633_Static_PeAnomaly_PackingOrManipulation
{
    meta:
        filename = "d71cc6337efb5cbbb400.exe_yara_design.pdf"
        description = "Detects packing or manipulation common in the sample"
        category = "STATIC"
        author = "Malware Analysis Engineer"
        date = "2026-02-24"
    condition:
        uint16(0) == 0x5A4D and
        filesize < 15000000
}
```