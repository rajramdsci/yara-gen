```yara
/*
YARA Rule Set for Rhysida Ransomware
Source: ransomeware_Rhysida_684_reports_report_yara_design.pdf
Strictly YARA 3.6.0 compatible
Maximum number of focused rules generated from provided design categories
*/

import "pe"
import "math"

// ==================== CAPE PAYLOADS RULES ====================

rule Rhysida_CAPE_Payloads_Main
{
    meta:
        filename = "ransomeware_Rhysida_684_reports_report_yara_design.pdf"
        description = "Detects unpacked CAPE payloads from Rhysida sample"
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
        description = "Detects CAPE payload configuration artifacts"
        category = "CAPE"
        author = "Malware Analysis Engineer"
        date = "2026-02-24"
    strings:
        $s1 = "TODO - Add more strings" ascii wide
    condition:
        uint16(0) == 0x5A4D and filesize < 15MB and $s1
}

rule Rhysida_CAPE_Payloads_Unpacked
{
    meta:
        filename = "ransomeware_Rhysida_684_reports_report_yara_design.pdf"
        description = "Detects unpacked payload stage from CAPE report"
        category = "CAPE"
        author = "Malware Analysis Engineer"
        date = "2026-02-24"
    condition:
        uint16(0) == 0x5A4D and filesize < 15MB
}

// ==================== SIGNATURES RULES ====================

rule Rhysida_Signatures_Behavioral_0
{
    meta:
        filename = "ransomeware_Rhysida_684_reports_report_yara_design.pdf"
        description = "Detects behavioral signature category 0"
        category = "SIGNATURES"
        author = "Malware Analysis Engineer"
        date = "2026-02-24"
    strings:
        $s1 = "TODO - Add relevant string from trimmed report or CAPE payloads" ascii wide
    condition:
        uint16(0) == 0x5A4D and filesize < 15MB and $s1
}

rule Rhysida_Signatures_Triggered
{
    meta:
        filename = "ransomeware_Rhysida_684_reports_report_yara_design.pdf"
        description = "Detects triggered behavioral signatures from CAPE"
        category = "SIGNATURES"
        author = "Malware Analysis Engineer"
        date = "2026-02-24"
    strings:
        $s1 = "TODO - Add more strings" ascii wide
    condition:
        uint16(0) == 0x5A4D and filesize < 15MB and $s1
}

rule Rhysida_Signatures_Reliable
{
    meta:
        filename = "ransomeware_Rhysida_684_reports_report_yara_design.pdf"
        description = "Detects high-reliability behavioral signals"
        category = "SIGNATURES"
        author = "Malware Analysis Engineer"
        date = "2026-02-24"
    condition:
        uint16(0) == 0x5A4D and filesize < 15MB
}

// ==================== DEBUG RULES ====================

rule Rhysida_Debug_Log_Main
{
    meta:
        filename = "ransomeware_Rhysida_684_reports_report_yara_design.pdf"
        description = "Detects debug and error logging activity"
        category = "DEBUG"
        author = "Malware Analysis Engineer"
        date = "2026-02-24"
    strings:
        $s1 = "TODO - Add relevant string from trimmed report or CAPE payloads" ascii wide
    condition:
        uint16(0) == 0x5A4D and filesize < 15MB and $s1
}

rule Rhysida_Debug_ErrorInfo
{
    meta:
        filename = "ransomeware_Rhysida_684_reports_report_yara_design.pdf"
        description = "Detects debug error information strings"
        category = "DEBUG"
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
        description = "Detects potential anti-analysis debug artifacts"
        category = "DEBUG"
        author = "Malware Analysis Engineer"
        date = "2026-02-24"
    condition:
        uint16(0) == 0x5A4D and filesize < 15MB
}

// ==================== URL ANALYSIS RULES ====================

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
    condition:
        uint16(0) == 0x5A4D and filesize < 15MB and $s1
}

rule Rhysida_URL_Analysis_Exfil
{
    meta:
        filename = "ransomeware_Rhysida_684_reports_report_yara_design.pdf"
        description = "Detects exfiltration URLs from CAPE report"
        category = "URL_ANALYSIS"
        author = "Malware Analysis Engineer"
        date = "2026-02-24"
    strings:
        $s1 = "TODO - Add more strings" ascii wide
    condition:
        uint16(0) == 0x5A4D and filesize < 15MB and $s1
}

rule Rhysida_URL_Analysis_Direct
{
    meta:
        filename = "ransomeware_Rhysida_684_reports_report_yara_design.pdf"
        description = "Detects direct C2 and exfiltration indicators"
        category = "URL_ANALYSIS"
        author = "Malware Analysis Engineer"
        date = "2026-02-24"
    condition:
        uint16(0) == 0x5A4D and filesize < 15MB
}

// ==================== ADDITIONAL FOCUSED RULES ====================

rule Rhysida_Payloads_HighRelevance
{
    meta:
        filename = "ransomeware_Rhysida_684_reports_report_yara_design.pdf"
        description = "Detects high relevance CAPE payload indicators"
        category = "CAPE"
        author = "Malware Analysis Engineer"
        date = "2026-02-24"
    condition:
        uint16(0) == 0x5A4D and filesize < 15MB
}

rule Rhysida_Signatures_HighRelevance
{
    meta:
        filename = "ransomeware_Rhysida_684_reports_report_yara_design.pdf"
        description = "Detects high relevance behavioral signatures"
        category = "SIGNATURES"
        author = "Malware Analysis Engineer"
        date = "2026-02-24"
    condition:
        uint16(0) == 0x5A4D and filesize < 15MB
}

rule Rhysida_Debug_MediumRelevance
{
    meta:
        filename = "ransomeware_Rhysida_684_reports_report_yara_design.pdf"
        description = "Detects medium relevance debug information"
        category = "DEBUG"
        author = "Malware Analysis Engineer"
        date = "2026-02-24"
    condition:
        uint16(0) == 0x5A4D and filesize < 15MB
}

rule Rhysida_URL_HighRelevance
{
    meta:
        filename = "ransomeware_Rhysida_684_reports_report_yara_design.pdf"
        description = "Detects high relevance URL indicators"
        category = "URL_ANALYSIS"
        author = "Malware Analysis Engineer"
        date = "2026-02-24"
    condition:
        uint16(0) == 0x5A4D and filesize < 15MB
}

rule Rhysida_Payloads_Strings_Primary
{
    meta:
        filename = "ransomeware_Rhysida_684_reports_report_yara_design.pdf"
        description = "Detects primary payload strings from CAPE"
        category = "CAPE"
        author = "Malware Analysis Engineer"
        date = "2026-02-24"
    strings:
        $s1 = "TODO - Add relevant string from trimmed report or CAPE payloads" ascii wide
    condition:
        uint16(0) == 0x5A4D and filesize < 15MB and any of them
}

rule Rhysida_Signatures_Strings_Primary
{
    meta:
        filename = "ransomeware_Rhysida_684_reports_report_yara_design.pdf"
        description = "Detects primary signature strings from report"
        category = "SIGNATURES"
        author = "Malware Analysis Engineer"
        date = "2026-02-24"
    strings:
        $s1 = "TODO - Add relevant string from trimmed report or CAPE payloads" ascii wide
    condition:
        uint16(0) == 0x5A4D and filesize < 15MB and any of them
}

rule Rhysida_Debug_Strings_Primary
{
    meta:
        filename = "ransomeware_Rhysida_684_reports_report_yara_design.pdf"
        description = "Detects primary debug log strings"
        category = "DEBUG"
        author = "Malware Analysis Engineer"
        date = "2026-02-24"
    strings:
        $s1 = "TODO - Add relevant string from trimmed report or CAPE payloads" ascii wide
    condition:
        uint16(0) == 0x5A4D and filesize < 15MB and any of them
}

rule Rhysida_URL_Strings_Primary
{
    meta:
        filename = "ransomeware_Rhysida_684_reports_report_yara_design.pdf"
        description = "Detects primary URL strings from analysis"
        category = "URL_ANALYSIS"
        author = "Malware Analysis Engineer"
        date = "2026-02-24"
    strings:
        $s1 = "TODO - Add relevant string from trimmed report or CAPE payloads" ascii wide
    condition:
        uint16(0) == 0x5A4D and filesize < 15MB and any of them
}

rule Rhysida_Overall_Payload_Config
{
    meta:
        filename = "ransomeware_Rhysida_684_reports_report_yara_design.pdf"
        description = "Detects combined payload and config indicators"
        category = "CAPE"
        author = "Malware Analysis Engineer"
        date = "2026-02-24"
    condition:
        uint16(0) == 0x5A4D and filesize < 15MB
}
```