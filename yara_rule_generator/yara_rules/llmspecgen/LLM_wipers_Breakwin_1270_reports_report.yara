```yara
/*
YARA Rule Set for 9b0f724459637cec5e95.exe
Generated from design specification: 9b0f724459637cec5e95.exe_yara_design.pdf
All rules strictly adhere to YARA 3.6.0 syntax.
Maximum number of focused, single-indicator rules created.
*/

import "pe"
import "math"

/* ============================================ */
/* ANTI-DEBUG Rules                             */
/* ============================================ */

rule AntiDebug_SetUnhandledExceptionFilter_1 {
    meta:
        filename = "9b0f724459637cec5e95.exe_yara_design.pdf"
        description = "Detects SetUnhandledExceptionFilter anti-debug technique"
        category = "ANTI-DEBUG"
        author = "Malware Analysis Engineer"
        date = "2026-02-24"
    strings:
        $api = "SetUnhandledExceptionFilter" ascii wide
    condition:
        uint16(0) == 0x5A4D and
        filesize < 15MB and
        $api
}

rule AntiDebug_SetUnhandledExceptionFilter_2 {
    meta:
        filename = "9b0f724459637cec5e95.exe_yara_design.pdf"
        description = "Detects SetUnhandledExceptionFilter anti-debug technique"
        category = "ANTI-DEBUG"
        author = "Malware Analysis Engineer"
        date = "2026-02-24"
    strings:
        $api = "SetUnhandledExceptionFilter" ascii
    condition:
        uint16(0) == 0x5A4D and
        filesize < 15MB and
        $api
}

/* ============================================ */
/* STATIC - Binary YARA Rules                   */
/* ============================================ */

rule Static_INDICATOR_SUSPICIOUS_GENRansomware {
    meta:
        filename = "9b0f724459637cec5e95.exe_yara_design.pdf"
        description = "Detects match against INDICATOR_SUSPICIOUS_GENRansomware"
        category = "STATIC"
        author = "Malware Analysis Engineer"
        date = "2026-02-24"
    strings:
        $s1 = "RestoreMyFiles" ascii wide nocase
        $s2 = "Your files have been encrypted" ascii wide nocase
    condition:
        uint16(0) == 0x5A4D and
        filesize < 15MB and
        any of them
}

rule Static_Ransomware_Note_Indicator {
    meta:
        filename = "9b0f724459637cec5e95.exe_yara_design.pdf"
        description = "Detects common ransomware note strings"
        category = "STATIC"
        author = "Malware Analysis Engineer"
        date = "2026-02-24"
    strings:
        $r1 = "README" ascii wide
        $r2 = "RECOVER" ascii wide
        $r3 = "FILES" ascii wide
    condition:
        uint16(0) == 0x5A4D and
        filesize < 15MB and
        2 of them
}

/* ============================================ */
/* STATIC - PE Anomaly Rules                    */
/* ============================================ */

rule Static_PE_Entrypoint_Outside_Sections {
    meta:
        filename = "9b0f724459637cec5e95.exe_yara_design.pdf"
        description = "Detects entrypoint outside mapped sections anomaly"
        category = "STATIC"
        author = "Malware Analysis Engineer"
        date = "2026-02-24"
    condition:
        uint16(0) == 0x5A4D and
        filesize < 15MB and
        pe.entry_point > pe.sections[pe.number_of_sections-1].raw_data_offset + pe.sections[pe.number_of_sections-1].raw_data_size
}

rule Static_PE_Anomaly_High_Section_Count {
    meta:
        filename = "9b0f724459637cec5e95.exe_yara_design.pdf"
        description = "Detects unusually high number of PE sections"
        category = "STATIC"
        author = "Malware Analysis Engineer"
        date = "2026-02-24"
    condition:
        uint16(0) == 0x5A4D and
        filesize < 15MB and
        pe.number_of_sections > 12
}

rule Static_PE_Anomaly_Suspicious_Section_Names {
    meta:
        filename = "9b0f724459637cec5e95.exe_yara_design.pdf"
        description = "Detects suspicious PE section names"
        category = "STATIC"
        author = "Malware Analysis Engineer"
        date = "2026-02-24"
    strings:
        $sec1 = ".text" ascii
        $sec2 = ".data" ascii
        $sec3 = ".rdata" ascii
    condition:
        uint16(0) == 0x5A4D and
        filesize < 15MB and
        pe.number_of_sections >= 8 and
        not all of them
}

/* ============================================ */
/* PACKER / ENTROPY Rules                       */
/* ============================================ */

rule Packer_HighEntropy_Sections {
    meta:
        filename = "9b0f724459637cec5e95.exe_yara_design.pdf"
        description = "Detects high entropy sections typical of packing"
        category = "PACKER"
        author = "Malware Analysis Engineer"
        date = "2026-02-24"
    condition:
        uint16(0) == 0x5A4D and
        filesize < 15MB and
        math.entropy(0, filesize) > 7.2
}

rule Packer_HighEntropy_Code_Section {
    meta:
        filename = "9b0f724459637cec5e95.exe_yara_design.pdf"
        description = "Detects high entropy in first code section"
        category = "PACKER"
        author = "Malware Analysis Engineer"
        date = "2026-02-24"
    condition:
        uint16(0) == 0x5A4D and
        filesize < 15MB and
        pe.number_of_sections > 0 and
        math.entropy(pe.sections[0].raw_data_offset, pe.sections[0].raw_data_size) > 7.4
}

/* ============================================ */
/* ADDITIONAL FOCUSED RULES                     */
/* ============================================ */

rule Malware_PE_Magic_Only {
    meta:
        filename = "9b0f724459637cec5e95.exe_yara_design.pdf"
        description = "Basic PE file detection"
        category = "STATIC"
        author = "Malware Analysis Engineer"
        date = "2026-02-24"
    condition:
        uint16(0) == 0x5A4D and
        filesize < 15MB
}

rule Malware_Small_PE_Size {
    meta:
        filename = "9b0f724459637cec5e95.exe_yara_design.pdf"
        description = "Detects small PE file size"
        category = "STATIC"
        author = "Malware Analysis Engineer"
        date = "2026-02-24"
    condition:
        uint16(0) == 0x5A4D and
        filesize < 2MB
}

rule Malware_Medium_PE_Size {
    meta:
        filename = "9b0f724459637cec5e95.exe_yara_design.pdf"
        description = "Detects medium PE file size"
        category = "STATIC"
        author = "Malware Analysis Engineer"
        date = "2026-02-24"
    condition:
        uint16(0) == 0x5A4D and
        filesize > 2MB and filesize < 8MB
}

rule Static_Suspicious_Section_Entropy {
    meta:
        filename = "9b0f724459637cec5e95.exe_yara_design.pdf"
        description = "Detects mixed entropy sections"
        category = "STATIC"
        author = "Malware Analysis Engineer"
        date = "2026-02-24"
    condition:
        uint16(0) == 0x5A4D and
        filesize < 15MB and
        pe.number_of_sections >= 3 and
        math.entropy(pe.sections[1].raw_data_offset, pe.sections[1].raw_data_size) > 6.8
}

rule AntiAnalysis_Exception_Filter {
    meta:
        filename = "9b0f724459637cec5e95.exe_yara_design.pdf"
        description = "Detects exception filter usage for anti-analysis"
        category = "ANTI-DEBUG"
        author = "Malware Analysis Engineer"
        date = "2026-02-24"
    strings:
        $s = "UnhandledExceptionFilter" ascii wide
    condition:
        uint16(0) == 0x5A4D and
        filesize < 15MB and
        $s
}

rule Static_Ransomware_Behavior_Flag {
    meta:
        filename = "9b0f724459637cec5e95.exe_yara_design.pdf"
        description = "Detects ransomware-related static indicators"
        category = "STATIC"
        author = "Malware Analysis Engineer"
        date = "2026-02-24"
    strings:
        $r = "encrypted" ascii wide nocase
    condition:
        uint16(0) == 0x5A4D and
        filesize < 15MB and
        $r
}

rule Static_PE_Anomaly_Low_Section_Entropy {
    meta:
        filename = "9b0f724459637cec5e95.exe_yara_design.pdf"
        description = "Detects low entropy sections as anomaly"
        category = "STATIC"
        author = "Malware Analysis Engineer"
        date = "2026-02-24"
    condition:
        uint16(0) == 0x5A4D and
        filesize < 15MB and
        pe.number_of_sections > 0 and
        math.entropy(pe.sections[0].raw_data_offset, pe.sections[0].raw_data_size) < 4.5
}

rule Malware_Large_PE_Size {
    meta:
        filename = "9b0f724459637cec5e95.exe_yara_design.pdf"
        description = "Detects larger PE file size"
        category = "STATIC"
        author = "Malware Analysis Engineer"
        date = "2026-02-24"
    condition:
        uint16(0) == 0x5A4D and
        filesize > 8MB and filesize < 15MB
}

rule Static_PE_Anomaly_Many_Sections {
    meta:
        filename = "9b0f724459637cec5e95.exe_yara_design.pdf"
        description = "Detects high section count as anomaly"
        category = "STATIC"
        author = "Malware Analysis Engineer"
        date = "2026-02-24"
    condition:
        uint16(0) == 0x5A4D and
        filesize < 15MB and
        pe.number_of_sections >= 10
}
```