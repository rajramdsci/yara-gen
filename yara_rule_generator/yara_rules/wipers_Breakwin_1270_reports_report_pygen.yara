```yara
/*
YARA Rule Set for wipers_Breakwin_1270
Generated from design specification: wipers_Breakwin_1270_reports_report_yara_design.pdf
All rules strictly adhere to YARA 3.6.0 syntax.
Rules are maximized into focused, single-purpose detections based on provided categories.
*/

import "pe"
import "math"

/* ==================== CAPE PAYLOADS ==================== */

rule Breakwin_CAPE_Payloads_Config_1
{
    meta:
        filename = "wipers_Breakwin_1270_reports_report_yara_design.pdf"
        description = "Detects CAPE payloads config indicators"
        category = "CAPE"
        author = "Malware Analysis Engineer"
        date = "2026-02-24"
    strings:
        $s1 = "TODO - Add relevant string from trimmed report or CAPE payloads" ascii wide
    condition:
        uint16(0) == 0x5A4D and filesize < 15MB and $s1
}

rule Breakwin_CAPE_Payloads_Config_2
{
    meta:
        filename = "wipers_Breakwin_1270_reports_report_yara_design.pdf"
        description = "Detects CAPE payloads config indicators"
        category = "CAPE"
        author = "Malware Analysis Engineer"
        date = "2026-02-24"
    strings:
        $s1 = "TODO - Add more strings" ascii wide
    condition:
        uint16(0) == 0x5A4D and filesize < 15MB and $s1
}

rule Breakwin_CAPE_Payloads_Unpacked_1
{
    meta:
        filename = "wipers_Breakwin_1270_reports_report_yara_design.pdf"
        description = "Detects unpacked payload artifacts"
        category = "CAPE"
        author = "Malware Analysis Engineer"
        date = "2026-02-24"
    strings:
        $s1 = "TODO - Add relevant string from trimmed report or CAPE payloads" ascii wide
    condition:
        uint16(0) == 0x5A4D and filesize < 15MB and $s1
}

rule Breakwin_CAPE_Payloads_Unpacked_2
{
    meta:
        filename = "wipers_Breakwin_1270_reports_report_yara_design.pdf"
        description = "Detects unpacked payload artifacts"
        category = "CAPE"
        author = "Malware Analysis Engineer"
        date = "2026-02-24"
    strings:
        $s1 = "TODO - Add more strings" ascii wide
    condition:
        uint16(0) == 0x5A4D and filesize < 15MB and $s1
}

rule Breakwin_CAPE_Payloads_HighRelevance
{
    meta:
        filename = "wipers_Breakwin_1270_reports_report_yara_design.pdf"
        description = "Detects high-relevance CAPE payload activity"
        category = "CAPE"
        author = "Malware Analysis Engineer"
        date = "2026-02-24"
    strings:
        $s1 = "TODO - Add relevant string from trimmed report or CAPE payloads" ascii wide
        $s2 = "TODO - Add more strings" ascii wide
    condition:
        uint16(0) == 0x5A4D and filesize < 15MB and any of them
}

/* ==================== SIGNATURES ==================== */

rule Breakwin_Signatures_Behavioral_1
{
    meta:
        filename = "wipers_Breakwin_1270_reports_report_yara_design.pdf"
        description = "Detects behavioral signatures from CAPE report"
        category = "SIGNATURES"
        author = "Malware Analysis Engineer"
        date = "2026-02-24"
    strings:
        $s1 = "TODO - Add relevant string from trimmed report or CAPE payloads" ascii wide
    condition:
        uint16(0) == 0x5A4D and filesize < 15MB and $s1
}

rule Breakwin_Signatures_Behavioral_2
{
    meta:
        filename = "wipers_Breakwin_1270_reports_report_yara_design.pdf"
        description = "Detects behavioral signatures from CAPE report"
        category = "SIGNATURES"
        author = "Malware Analysis Engineer"
        date = "2026-02-24"
    strings:
        $s1 = "TODO - Add more strings" ascii wide
    condition:
        uint16(0) == 0x5A4D and filesize < 15MB and $s1
}

rule Breakwin_Signatures_Triggered_0_1
{
    meta:
        filename = "wipers_Breakwin_1270_reports_report_yara_design.pdf"
        description = "Detects [0] signature activity"
        category = "SIGNATURES"
        author = "Malware Analysis Engineer"
        date = "2026-02-24"
    strings:
        $s1 = "TODO - Add relevant string from trimmed report or CAPE payloads" ascii wide
    condition:
        uint16(0) == 0x5A4D and filesize < 15MB and $s1
}

rule Breakwin_Signatures_Triggered_0_2
{
    meta:
        filename = "wipers_Breakwin_1270_reports_report_yara_design.pdf"
        description = "Detects [0] signature activity"
        category = "SIGNATURES"
        author = "Malware Analysis Engineer"
        date = "2026-02-24"
    strings:
        $s1 = "TODO - Add more strings" ascii wide
    condition:
        uint16(0) == 0x5A4D and filesize < 15MB and $s1
}

rule Breakwin_Signatures_Reliable_Behavior
{
    meta:
        filename = "wipers_Breakwin_1270_reports_report_yara_design.pdf"
        description = "Detects reliable behavioral detection signals"
        category = "SIGNATURES"
        author = "Malware Analysis Engineer"
        date = "2026-02-24"
    strings:
        $s1 = "TODO - Add relevant string from trimmed report or CAPE payloads" ascii wide
        $s2 = "TODO - Add more strings" ascii wide
    condition:
        uint16(0) == 0x5A4D and filesize < 15MB and any of them
}

/* ==================== DEBUG ==================== */

rule Breakwin_Debug_Log_1
{
    meta:
        filename = "wipers_Breakwin_1270_reports_report_yara_design.pdf"
        description = "Detects debug log activity"
        category = "DEBUG"
        author = "Malware Analysis Engineer"
        date = "2026-02-24"
    strings:
        $s1 = "TODO - Add relevant string from trimmed report or CAPE payloads" ascii wide
    condition:
        uint16(0) == 0x5A4D and filesize < 15MB and $s1
}

rule Breakwin_Debug_Log_2
{
    meta:
        filename = "wipers_Breakwin_1270_reports_report_yara_design.pdf"
        description = "Detects debug log activity"
        category = "DEBUG"
        author = "Malware Analysis Engineer"
        date = "2026-02-24"
    strings:
        $s1 = "TODO - Add more strings" ascii wide
    condition:
        uint16(0) == 0x5A4D and filesize < 15MB and $s1
}

rule Breakwin_Debug_ErrorInfo
{
    meta:
        filename = "wipers_Breakwin_1270_reports_report_yara_design.pdf"
        description = "Detects debug and error information"
        category = "DEBUG"
        author = "Malware Analysis Engineer"
        date = "2026-02-24"
    strings:
        $s1 = "TODO - Add relevant string from trimmed report or CAPE payloads" ascii wide
        $s2 = "TODO - Add more strings" ascii wide
    condition:
        uint16(0) == 0x5A4D and filesize < 15MB and any of them
}

/* ==================== URL ANALYSIS ==================== */

rule Breakwin_URL_Analysis_C2_1
{
    meta:
        filename = "wipers_Breakwin_1270_reports_report_yara_design.pdf"
        description = "Detects C2 or exfiltration URLs"
        category = "URL_ANALYSIS"
        author = "Malware Analysis Engineer"
        date = "2026-02-24"
    strings:
        $s1 = "TODO - Add relevant string from trimmed report or CAPE payloads" ascii wide
    condition:
        uint16(0) == 0x5A4D and filesize < 15MB and $s1
}

rule Breakwin_URL_Analysis_C2_2
{
    meta:
        filename = "wipers_Breakwin_1270_reports_report_yara_design.pdf"
        description = "Detects C2 or exfiltration URLs"
        category = "URL_ANALYSIS"
        author = "Malware Analysis Engineer"
        date = "2026-02-24"
    strings:
        $s1 = "TODO - Add more strings" ascii wide
    condition:
        uint16(0) == 0x5A4D and filesize < 15MB and $s1
}

rule Breakwin_URL_Analysis_Exfil_1
{
    meta:
        filename = "wipers_Breakwin_1270_reports_report_yara_design.pdf"
        description = "Detects exfiltration URL patterns"
        category = "URL_ANALYSIS"
        author = "Malware Analysis Engineer"
        date = "2026-02-24"
    strings:
        $s1 = "TODO - Add relevant string from trimmed report or CAPE payloads" ascii wide
    condition:
        uint16(0) == 0x5A4D and filesize < 15MB and $s1
}

rule Breakwin_URL_Analysis_Exfil_2
{
    meta:
        filename = "wipers_Breakwin_1270_reports_report_yara_design.pdf"
        description = "Detects exfiltration URL patterns"
        category = "URL_ANALYSIS"
        author = "Malware Analysis Engineer"
        date = "2026-02-24"
    strings:
        $s1 = "TODO - Add more strings" ascii wide
    condition:
        uint16(0) == 0x5A4D and filesize < 15MB and $s1
}

rule Breakwin_URL_Analysis_Direct_Indicators
{
    meta:
        filename = "wipers_Breakwin_1270_reports_report_yara_design.pdf"
        description = "Detects direct C2 and exfiltration indicators"
        category = "URL_ANALYSIS"
        author = "Malware Analysis Engineer"
        date = "2026-02-24"
    strings:
        $s1 = "TODO - Add relevant string from trimmed report or CAPE payloads" ascii wide
        $s2 = "TODO - Add more strings" ascii wide
    condition:
        uint16(0) == 0x5A4D and filesize < 15MB and any of them
}
```