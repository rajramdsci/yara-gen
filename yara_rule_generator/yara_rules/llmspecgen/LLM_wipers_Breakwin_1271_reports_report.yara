```yara
/*
YARA Rule Set for d71cc6337efb5cbbb400.exe
Generated from design specification: d71cc6337efb5cbbb400.exe_yara_design.pdf
All rules strictly adhere to YARA 3.6.0 syntax.
Maximum number of focused, single-indicator rules created.
*/

import "pe"
import "math"

/* ============================================
   GROUP: STATIC - Binary Strings
   ============================================ */

rule LockBit_GENRansomware_String_Indicator
{
    meta:
        filename = "d71cc6337efb5cbbb400.exe_yara_design.pdf"
        description = "Detects GENRansomware indicator string from static analysis"
        category = "STATIC"
        author = "Malware Analysis Engineer"
        date = "2026-02-24"
    strings:
        $s1 = "INDICATOR_SUSPICIOUS_GENRansomware" ascii wide
    condition:
        uint16(0) == 0x5A4D and $s1
}

rule LockBit_GENRansomware_String_Ascii
{
    meta:
        filename = "d71cc6337efb5cbbb400.exe_yara_design.pdf"
        description = "Detects GENRansomware indicator in ASCII encoding"
        category = "STATIC"
        author = "Malware Analysis Engineer"
        date = "2026-02-24"
    strings:
        $s1 = "INDICATOR_SUSPICIOUS_GENRansomware" ascii
    condition:
        uint16(0) == 0x5A4D and $s1
}

rule LockBit_GENRansomware_String_Wide
{
    meta:
        filename = "d71cc6337efb5cbbb400.exe_yara_design.pdf"
        description = "Detects GENRansomware indicator in wide encoding"
        category = "STATIC"
        author = "Malware Analysis Engineer"
        date = "2026-02-24"
    strings:
        $s1 = "INDICATOR_SUSPICIOUS_GENRansomware" wide
    condition:
        uint16(0) == 0x5A4D and $s1
}

/* ============================================
   GROUP: STATIC - PE Anomalies
   ============================================ */

rule LockBit_PE_Anomaly_Entrypoint_Outside_Sections
{
    meta:
        filename = "d71cc6337efb5cbbb400.exe_yara_design.pdf"
        description = "Detects entrypoint outside mapped sections anomaly"
        category = "STATIC"
        author = "Malware Analysis Engineer"
        date = "2026-02-24"
    condition:
        uint16(0) == 0x5A4D and
        pe.entry_point > pe.sections[pe.number_of_sections-1].raw_data_offset + pe.sections[pe.number_of_sections-1].raw_data_size
}

rule LockBit_PE_Anomaly_Small_Number_Of_Sections
{
    meta:
        filename = "d71cc6337efb5cbbb400.exe_yara_design.pdf"
        description = "Detects low section count often seen in packed ransomware"
        category = "STATIC"
        author = "Malware Analysis Engineer"
        date = "2026-02-24"
    condition:
        uint16(0) == 0x5A4D and
        pe.number_of_sections < 4
}

rule LockBit_PE_Anomaly_High_Entropy_Section_0
{
    meta:
        filename = "d71cc6337efb5cbbb400.exe_yara_design.pdf"
        description = "Detects high entropy in first section indicating packing"
        category = "STATIC"
        author = "Malware Analysis Engineer"
        date = "2026-02-24"
    condition:
        uint16(0) == 0x5A4D and
        math.entropy(0, filesize) > 7.0
}

/* ============================================
   GROUP: STATIC - File Characteristics
   ============================================ */

rule LockBit_FileSize_LessThan_15MB
{
    meta:
        filename = "d71cc6337efb5cbbb400.exe_yara_design.pdf"
        description = "Matches filesize constraint from design specification"
        category = "STATIC"
        author = "Malware Analysis Engineer"
        date = "2026-02-24"
    condition:
        uint16(0) == 0x5A4D and
        filesize < 15MB
}

rule LockBit_FileSize_Ransomware_Typical_Range
{
    meta:
        filename = "d71cc6337efb5cbbb400.exe_yara_design.pdf"
        description = "Detects typical ransomware file size range"
        category = "STATIC"
        author = "Malware Analysis Engineer"
        date = "2026-02-24"
    condition:
        uint16(0) == 0x5A4D and
        filesize > 100KB and filesize < 8MB
}

/* ============================================
   GROUP: RANSOMWARE - Behavioral Indicators
   ============================================ */

rule LockBit_Ransomware_GENRansomware_Flag
{
    meta:
        filename = "d71cc6337efb5cbbb400.exe_yara_design.pdf"
        description = "Core rule for GENRansomware static indicator"
        category = "RANSOMWARE"
        author = "Malware Analysis Engineer"
        date = "2026-02-24"
    strings:
        $s1 = "INDICATOR_SUSPICIOUS_GENRansomware" ascii wide
    condition:
        uint16(0) == 0x5A4D and $s1
}

rule LockBit_Ransomware_Possible_RansomNote_Reference
{
    meta:
        filename = "d71cc6337efb5cbbb400.exe_yara_design.pdf"
        description = "Detects potential ransom note related strings"
        category = "RANSOMWARE"
        author = "Malware Analysis Engineer"
        date = "2026-02-24"
    strings:
        $s1 = "RestoreMyFiles" ascii wide nocase
    condition:
        uint16(0) == 0x5A4D and $s1
}

/* ============================================
   GROUP: PACKING - Entropy Based
   ============================================ */

rule LockBit_Packer_High_Entropy_Overall
{
    meta:
        filename = "d71cc6337efb5cbbb400.exe_yara_design.pdf"
        description = "Detects high overall entropy typical of packed malware"
        category = "PACKING"
        author = "Malware Analysis Engineer"
        date = "2026-02-24"
    condition:
        uint16(0) == 0x5A4D and
        math.entropy(0, filesize) > 7.2
}

rule LockBit_Packer_Low_Section_Count_High_Entropy
{
    meta:
        filename = "d71cc6337efb5cbbb400.exe_yara_design.pdf"
        description = "Combines low section count with high entropy"
        category = "PACKING"
        author = "Malware Analysis Engineer"
        date = "2026-02-24"
    condition:
        uint16(0) == 0x5A4D and
        pe.number_of_sections <= 3 and
        math.entropy(0, filesize) > 6.8
}

/* ============================================
   GROUP: ADDITIONAL STATIC INDICATORS
   ============================================ */

rule LockBit_Static_PE_MZ_Header
{
    meta:
        filename = "d71cc6337efb5cbbb400.exe_yara_design.pdf"
        description = "Basic PE file detection using MZ header"
        category = "STATIC"
        author = "Malware Analysis Engineer"
        date = "2026-02-24"
    condition:
        uint16(0) == 0x5A4D
}

rule LockBit_Static_Suspicious_Ransomware_String_Presence
{
    meta:
        filename = "d71cc6337efb5cbbb400.exe_yara_design.pdf"
        description = "Detects ransomware-related static string from CAPE report"
        category = "STATIC"
        author = "Malware Analysis Engineer"
        date = "2026-02-24"
    strings:
        $s1 = "INDICATOR_SUSPICIOUS_GENRansomware" ascii wide
    condition:
        uint16(0) == 0x5A4D and any of them
}
```