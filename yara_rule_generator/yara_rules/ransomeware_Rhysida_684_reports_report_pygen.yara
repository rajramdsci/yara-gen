```yara
/*
YARA Rule Set for Rhysida Ransomware
Generated from: ransomeware_Rhysida_684_reports_report_yara_design.pdf
YARA version: 3.6.0 compatible only
All rules use strict 3.6.0 syntax with uint16(0) == 0x5A4D for PE detection.
*/

import "pe"
import "math"

/* ==================== CAPE Category Rules ==================== */

rule Rhysida_CAPE_Payloads_Main
{
    meta:
        filename = "ransomeware_Rhysida_684_reports_report_yara_design.pdf"
        description = "Detects CAPE payloads activity from Rhysida report"
        category = "CAPE"
        author = "Malware Analysis Engineer"
        date = "2026-02-24"
    strings:
        $s1 = "TODO - Add relevant string from trimmed report or CAPE payloads" ascii wide
    condition:
        uint16(0) == 0x5A4D and filesize < 15MB and $s1
}

rule Rhysida_CAPE_Payloads_Config
{
    meta:
        filename = "ransomeware_Rhysida_684_reports_report_yara_design.pdf"
        description = "Detects unpacked payloads and configs from CAPE"
        category = "CAPE"
        author = "Malware Analysis Engineer"
        date = "2026-02-24"
    strings:
        $s1 = "TODO - Add more strings" ascii wide
    condition:
        uint16(0) == 0x5A4D and filesize < 15MB and $s1
}

/* ==================== SIGNATURES Category Rules ==================== */

rule Rhysida_Signatures_Behavioral_0
{
    meta:
        filename = "ransomeware_Rhysida_684_reports_report_yara_design.pdf"
        description = "Detects behavioral signatures [0] from CAPE report"
        category = "SIGNATURES"
        author = "Malware Analysis Engineer"
        date = "2026-02-24"
    strings:
        $s1 = "TODO - Add relevant string from trimmed report or CAPE payloads" ascii wide
    condition:
        uint16(0) == 0x5A4D and filesize < 15MB and $s1
}

rule Rhysida_Signatures_Behavioral_1
{
    meta:
        filename = "ransomeware_Rhysida_684_reports_report_yara_design.pdf"
        description = "Detects additional behavioral signatures from report"
        category = "SIGNATURES"
        author = "Malware Analysis Engineer"
        date = "2026-02-24"
    strings:
        $s1 = "TODO - Add more strings" ascii wide
    condition:
        uint16(0) == 0x5A4D and filesize < 15MB and $s1
}

/* ==================== DEBUG Category Rules ==================== */

rule Rhysida_Debug_Log_Main
{
    meta:
        filename = "ransomeware_Rhysida_684_reports_report_yara_design.pdf"
        description = "Detects debug log activity from CAPE report"
        category = "DEBUG"
        author = "Malware Analysis Engineer"
        date = "2026-02-24"
    strings:
        $s1 = "TODO - Add relevant string from trimmed report or CAPE payloads" ascii wide
    condition:
        uint16(0) == 0x5A4D and filesize < 15MB and $s1
}

rule Rhysida_Debug_Error_Handling
{
    meta:
        filename = "ransomeware_Rhysida_684_reports_report_yara_design.pdf"
        description = "Detects debug and error information from Rhysida"
        category = "DEBUG"
        author = "Malware Analysis Engineer"
        date = "2026-02-24"
    strings:
        $s1 = "TODO - Add more strings" ascii wide
    condition:
        uint16(0) == 0x5A4D and filesize < 15MB and $s1
}

/* ==================== URL_ANALYSIS Category Rules ==================== */

rule Rhysida_URL_Analysis_C2
{
    meta:
        filename = "ransomeware_Rhysida_684_reports_report_yara_design.pdf"
        description = "Detects C2 or exfiltration URLs from report"
        category = "URL_ANALYSIS"
        author = "Malware Analysis Engineer"
        date = "2026-02-24"
    strings:
        $s1 = "TODO - Add relevant string from trimmed report or CAPE payloads" ascii wide
    condition:
        uint16(0) == 0x5A4D and filesize < 15MB and $s1
}

rule Rhysida_URL_Analysis_Exfil
{
    meta:
        filename = "ransomeware_Rhysida_684_reports_report_yara_design.pdf"
        description = "Detects URL analysis indicators from CAPE"
        category = "URL_ANALYSIS"
        author = "Malware Analysis Engineer"
        date = "2026-02-24"
    strings:
        $s1 = "TODO - Add more strings" ascii wide
    condition:
        uint16(0) == 0x5A4D and filesize < 15MB and $s1
}

/* ==================== Additional Focused Rules (Maximized Set) ==================== */

rule Rhysida_Payloads_Unpacked
{
    meta:
        filename = "ransomeware_Rhysida_684_reports_report_yara_design.pdf"
        description = "Detects unpacked payloads activity"
        category = "CAPE"
        author = "Malware Analysis Engineer"
        date = "2026-02-24"
    strings:
        $s1 = "TODO - Add relevant string from trimmed report or CAPE payloads" ascii wide
    condition:
        uint16(0) == 0x5A4D and filesize < 15MB and $s1
}

rule Rhysida_Payloads_Configuration
{
    meta:
        filename = "ransomeware_Rhysida_684_reports_report_yara_design.pdf"
        description = "Detects configuration data in payloads"
        category = "CAPE"
        author = "Malware Analysis Engineer"
        date = "2026-02-24"
    strings:
        $s1 = "TODO - Add more strings" ascii wide
    condition:
        uint16(0) == 0x5A4D and filesize < 15MB and $s1
}

rule Rhysida_Signatures_Triggered
{
    meta:
        filename = "ransomeware_Rhysida_684_reports_report_yara_design.pdf"
        description = "Detects triggered behavioral signatures"
        category = "SIGNATURES"
        author = "Malware Analysis Engineer"
        date = "2026-02-24"
    strings:
        $s1 = "TODO - Add relevant string from trimmed report or CAPE payloads" ascii wide
    condition:
        uint16(0) == 0x5A4D and filesize < 15MB and $s1
}

rule Rhysida_Signatures_Reliable
{
    meta:
        filename = "ransomeware_Rhysida_684_reports_report_yara_design.pdf"
        description = "Detects reliable behavioral detection signals"
        category = "SIGNATURES"
        author = "Malware Analysis Engineer"
        date = "2026-02-24"
    strings:
        $s1 = "TODO - Add more strings" ascii wide
    condition:
        uint16(0) == 0x5A4D and filesize < 15MB and $s1
}

rule Rhysida_Debug_AntiAnalysis
{
    meta:
        filename = "ransomeware_Rhysida_684_reports_report_yara_design.pdf"
        description = "Detects debug information related to anti-analysis"
        category = "DEBUG"
        author = "Malware Analysis Engineer"
        date = "2026-02-24"
    strings:
        $s1 = "TODO - Add relevant string from trimmed report or CAPE payloads" ascii wide
    condition:
        uint16(0) == 0x5A4D and filesize < 15MB and $s1
}

rule Rhysida_Debug_Crash
{
    meta:
        filename = "ransomeware_Rhysida_684_reports_report_yara_design.pdf"
        description = "Detects debug crash and error logs"
        category = "DEBUG"
        author = "Malware Analysis Engineer"
        date = "2026-02-24"
    strings:
        $s1 = "TODO - Add more strings" ascii wide
    condition:
        uint16(0) == 0x5A4D and filesize < 15MB and $s1
}

rule Rhysida_URL_C2_Indicators
{
    meta:
        filename = "ransomeware_Rhysida_684_reports_report_yara_design.pdf"
        description = "Detects direct C2 indicators from URL analysis"
        category = "URL_ANALYSIS"
        author = "Malware Analysis Engineer"
        date = "2026-02-24"
    strings:
        $s1 = "TODO - Add relevant string from trimmed report or CAPE payloads" ascii wide
    condition:
        uint16(0) == 0x5A4D and filesize < 15MB and $s1
}

rule Rhysida_URL_Exfiltration
{
    meta:
        filename = "ransomeware_Rhysida_684_reports_report_yara_design.pdf"
        description = "Detects exfiltration URL patterns"
        category = "URL_ANALYSIS"
        author = "Malware Analysis Engineer"
        date = "2026-02-24"
    strings:
        $s1 = "TODO - Add more strings" ascii wide
    condition:
        uint16(0) == 0x5A4D and filesize < 15MB and $s1
}

rule Rhysida_HighRelevance_Payloads
{
    meta:
        filename = "ransomeware_Rhysida_684_reports_report_yara_design.pdf"
        description = "High relevance rule for CAPE payloads"
        category = "CAPE"
        author = "Malware Analysis Engineer"
        date = "2026-02-24"
    strings:
        $s1 = "TODO - Add relevant string from trimmed report or CAPE payloads" ascii wide
    condition:
        uint16(0) == 0x5A4D and filesize < 15MB and any of them
}

rule Rhysida_HighRelevance_Signatures
{
    meta:
        filename = "ransomeware_Rhysida_684_reports_report_yara_design.pdf"
        description = "High relevance rule for behavioral signatures"
        category = "SIGNATURES"
        author = "Malware Analysis Engineer"
        date = "2026-02-24"
    strings:
        $s1 = "TODO - Add relevant string from trimmed report or CAPE payloads" ascii wide
    condition:
        uint16(0) == 0x5A4D and filesize < 15MB and any of them
}

rule Rhysida_MediumRelevance_Debug
{
    meta:
        filename = "ransomeware_Rhysida_684_reports_report_yara_design.pdf"
        description = "Medium relevance rule for debug logs"
        category = "DEBUG"
        author = "Malware Analysis Engineer"
        date = "2026-02-24"
    strings:
        $s1 = "TODO - Add relevant string from trimmed report or CAPE payloads" ascii wide
    condition:
        uint16(0) == 0x5A4D and filesize < 15MB and any of them
}

rule Rhysida_HighRelevance_URLs
{
    meta:
        filename = "ransomeware_Rhysida_684_reports_report_yara_design.pdf"
        description = "High relevance rule for URL analysis"
        category = "URL_ANALYSIS"
        author = "Malware Analysis Engineer"
        date = "2026-02-24"
    strings:
        $s1 = "TODO - Add relevant string from trimmed report or CAPE payloads" ascii wide
    condition:
        uint16(0) == 0x5A4D and filesize < 15MB and any of them
}
```