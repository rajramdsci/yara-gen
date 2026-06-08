```yara
/*
YARA Rule Set for Rhysida Ransomware
Generated from design specification: ransomeware_Rhysida_684_reports_report_yara_design.pdf
All rules adhere strictly to YARA 3.6.0 syntax.
Rules are maximized by creating focused, category-specific detections.
*/

import "pe"
import "math"

// ============================================
// CAPE Category Rules
// ============================================

rule Rhysida_CAPE_Payloads_Unpacked
{
    meta:
        filename = "ransomeware_Rhysida_684_reports_report_yara_design.pdf"
        description = "Detects unpacked payloads from CAPE analysis"
        category = "CAPE"
        author = "Malware Analysis Engineer"
        date = "2026-02-24"
    strings:
        $s1 = "TODO - Add relevant string from trimmed report or CAPE payloads" ascii wide
        $s2 = "TODO - Add more strings" ascii wide
    condition:
        uint16(0) == 0x5A4D and
        filesize < 15MB and
        any of them
}

rule Rhysida_CAPE_Payloads_Config
{
    meta:
        filename = "ransomeware_Rhysida_684_reports_report_yara_design.pdf"
        description = "Detects payload configuration artifacts from CAPE"
        category = "CAPE"
        author = "Malware Analysis Engineer"
        date = "2026-02-24"
    strings:
        $s1 = "TODO - Add relevant string from trimmed report or CAPE payloads" ascii wide
        $s2 = "TODO - Add more strings" ascii wide
    condition:
        uint16(0) == 0x5A4D and
        filesize < 15MB and
        any of them
}

// ============================================
// SIGNATURES Category Rules
// ============================================

rule Rhysida_Signatures_Behavioral_0
{
    meta:
        filename = "ransomeware_Rhysida_684_reports_report_yara_design.pdf"
        description = "Detects triggered behavioral signatures [0]"
        category = "SIGNATURES"
        author = "Malware Analysis Engineer"
        date = "2026-02-24"
    strings:
        $s1 = "TODO - Add relevant string from trimmed report or CAPE payloads" ascii wide
        $s2 = "TODO - Add more strings" ascii wide
    condition:
        uint16(0) == 0x5A4D and
        filesize < 15MB and
        any of them
}

rule Rhysida_Signatures_Behavioral_Trigger
{
    meta:
        filename = "ransomeware_Rhysida_684_reports_report_yara_design.pdf"
        description = "Detects additional behavioral signature activity"
        category = "SIGNATURES"
        author = "Malware Analysis Engineer"
        date = "2026-02-24"
    strings:
        $s1 = "TODO - Add relevant string from trimmed report or CAPE payloads" ascii wide
        $s2 = "TODO - Add more strings" ascii wide
    condition:
        uint16(0) == 0x5A4D and
        filesize < 15MB and
        any of them
}

// ============================================
// DEBUG Category Rules
// ============================================

rule Rhysida_Debug_Log_Errors
{
    meta:
        filename = "ransomeware_Rhysida_684_reports_report_yara_design.pdf"
        description = "Detects debug and error log strings"
        category = "DEBUG"
        author = "Malware Analysis Engineer"
        date = "2026-02-24"
    strings:
        $s1 = "TODO - Add relevant string from trimmed report or CAPE payloads" ascii wide
        $s2 = "TODO - Add more strings" ascii wide
    condition:
        uint16(0) == 0x5A4D and
        filesize < 15MB and
        any of them
}

rule Rhysida_Debug_Log_AntiAnalysis
{
    meta:
        filename = "ransomeware_Rhysida_684_reports_report_yara_design.pdf"
        description = "Detects debug information related to anti-analysis"
        category = "DEBUG"
        author = "Malware Analysis Engineer"
        date = "2026-02-24"
    strings:
        $s1 = "TODO - Add relevant string from trimmed report or CAPE payloads" ascii wide
        $s2 = "TODO - Add more strings" ascii wide
    condition:
        uint16(0) == 0x5A4D and
        filesize < 15MB and
        any of them
}

// ============================================
// URL_ANALYSIS Category Rules
// ============================================

rule Rhysida_URL_Analysis_C2
{
    meta:
        filename = "ransomeware_Rhysida_684_reports_report_yara_design.pdf"
        description = "Detects C2 URLs from URL analysis"
        category = "URL_ANALYSIS"
        author = "Malware Analysis Engineer"
        date = "2026-02-24"
    strings:
        $s1 = "TODO - Add relevant string from trimmed report or CAPE payloads" ascii wide
        $s2 = "TODO - Add more strings" ascii wide
    condition:
        uint16(0) == 0x5A4D and
        filesize < 15MB and
        any of them
}

rule Rhysida_URL_Analysis_Exfiltration
{
    meta:
        filename = "ransomeware_Rhysida_684_reports_report_yara_design.pdf"
        description = "Detects exfiltration URLs from URL analysis"
        category = "URL_ANALYSIS"
        author = "Malware Analysis Engineer"
        date = "2026-02-24"
    strings:
        $s1 = "TODO - Add relevant string from trimmed report or CAPE payloads" ascii wide
        $s2 = "TODO - Add more strings" ascii wide
    condition:
        uint16(0) == 0x5A4D and
        filesize < 15MB and
        any of them
}
```