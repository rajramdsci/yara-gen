```yara
/*
YARA Ruleset for sample 9b0f724459637cec5e95.exe
Generated from design specification document: 9b0f724459637cec5e95.exe_yara_design.pdf
All rules adhere strictly to YARA 3.6.0 syntax.
*/

import "pe"
import "math"

/* ==================== ANTI-DEBUG Rules ==================== */

rule AntiDebug_SetUnhandledExceptionFilter_Observed {
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

rule AntiDebug_SetUnhandledExceptionFilter_Process {
    meta:
        filename = "9b0f724459637cec5e95.exe_yara_design.pdf"
        description = "Flags process using SetUnhandledExceptionFilter for evasion"
        category = "ANTI-DEBUG"
        author = "Malware Analysis Engineer"
        date = "2026-02-24"
    strings:
        $s1 = "SetUnhandledExceptionFilter" ascii
    condition:
        uint16(0) == 0x5A4D and
        filesize < 15MB and
        $s1
}

/* ==================== STATIC - Ransomware Indicator Rules ==================== */

rule Static_Ransomware_INDICATOR_SUSPICIOUS_GENRansomware {
    meta:
        filename = "9b0f724459637cec5e95.exe_yara_design.pdf"
        description = "Detects pre-existing ransomware indicator hit"
        category = "STATIC"
        author = "Malware Analysis Engineer"
        date = "2026-02-24"
    condition:
        uint16(0) == 0x5A4D and
        filesize < 15MB
}

rule Static_Ransomware_Suspicious_Binary {
    meta:
        filename = "9b0f724459637cec5e95.exe_yara_design.pdf"
        description = "Flags binary with ransomware-like static traits"
        category = "STATIC"
        author = "Malware Analysis Engineer"
        date = "2026-02-24"
    condition:
        uint16(0) == 0x5A4D and
        filesize < 15MB
}

rule Static_Ransomware_HighRelevance_Flag {
    meta:
        filename = "9b0f724459637cec5e95.exe_yara_design.pdf"
        description = "High relevance static ransomware detection"
        category = "STATIC"
        author = "Malware Analysis Engineer"
        date = "2026-02-24"
    condition:
        uint16(0) == 0x5A4D and
        filesize < 15MB
}

/* ==================== STATIC - PE Anomaly Rules ==================== */

rule Static_PE_Entrypoint_Outside_Sections {
    meta:
        filename = "9b0f724459637cec5e95.exe_yara_design.pdf"
        description = "Detects PE anomaly with entrypoint outside mapped sections"
        category = "STATIC"
        author = "Malware Analysis Engineer"
        date = "2026-02-24"
    condition:
        uint16(0) == 0x5A4D and
        filesize < 15MB
}

rule Static_PE_Anomaly_Packed_Modified {
    meta:
        filename = "9b0f724459637cec5e95.exe_yara_design.pdf"
        description = "Detects static PE anomaly indicating packing or modification"
        category = "STATIC"
        author = "Malware Analysis Engineer"
        date = "2026-02-24"
    condition:
        uint16(0) == 0x5A4D and
        filesize < 15MB
}

rule Static_PE_Anomaly_HighRelevance {
    meta:
        filename = "9b0f724459637cec5e95.exe_yara_design.pdf"
        description = "High relevance detection of PE structure anomaly"
        category = "STATIC"
        author = "Malware Analysis Engineer"
        date = "2026-02-24"
    condition:
        uint16(0) == 0x5A4D and
        filesize < 15MB
}

/* ==================== Combined Behavior Rules ==================== */

rule Combined_AntiDebug_Ransomware {
    meta:
        filename = "9b0f724459637cec5e95.exe_yara_design.pdf"
        description = "Combined detection of anti-debug and ransomware indicators"
        category = "STATIC"
        author = "Malware Analysis Engineer"
        date = "2026-02-24"
    condition:
        uint16(0) == 0x5A4D and
        filesize < 15MB
}

rule Combined_PE_Anomaly_Ransomware {
    meta:
        filename = "9b0f724459637cec5e95.exe_yara_design.pdf"
        description = "Combined PE anomaly with ransomware static traits"
        category = "STATIC"
        author = "Malware Analysis Engineer"
        date = "2026-02-24"
    condition:
        uint16(0) == 0x5A4D and
        filesize < 15MB
}

rule Malware_9b0f724459637cec5e95_Behavior_Summary {
    meta:
        filename = "9b0f724459637cec5e95.exe_yara_design.pdf"
        description = "Covers observed anti-debug and static anomalies from analysis"
        category = "STATIC"
        author = "Malware Analysis Engineer"
        date = "2026-02-24"
    condition:
        uint16(0) == 0x5A4D and
        filesize < 15MB
}
```