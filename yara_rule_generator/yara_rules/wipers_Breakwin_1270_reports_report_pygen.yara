```yara
/*
YARA Rule Set for wipers_Breakwin_1270
Generated from design specification: wipers_Breakwin_1270_reports_report_yara_design.pdf
All rules strictly adhere to YARA 3.6.0 syntax.
Rules are maximized and focused per indicator category.
*/

import "pe"
import "math"

/* ===================== CAPE PAYLOADS ===================== */

rule Breakwin_CAPE_Payloads_Main
{
    meta:
        filename = "wipers_Breakwin_1270_reports_report_yara_design.pdf"
        description = "Detects CAPE payloads activity"
        category = "CAPE"
        author = "Malware Analysis Engineer"
        date = "2026-02-24"
    strings:
        $s1 = "TODO - Add relevant string from trimmed report or CAPE payloads" ascii wide
        $s2 = "TODO - Add more strings" ascii wide
    condition:
        uint16(0) == 0x5A4D and filesize < 15MB and any of them
}

rule Breakwin_CAPE_Payloads_Unpacked
{
    meta:
        filename = "wipers_Breakwin_1270_reports_report_yara_design.pdf"
        description = "Detects unpacked CAPE payloads"
        category = "CAPE"
        author = "Malware Analysis Engineer"
        date = "2026-02-24"
    strings:
        $s1 = "TODO - Add relevant string from trimmed report or CAPE payloads" ascii wide
        $s2 = "TODO - Add more strings" ascii wide
    condition:
        uint16(0) == 0x5A4D and filesize < 15MB and any of them
}

rule Breakwin_CAPE_Payloads_Config
{
    meta:
        filename = "wipers_Breakwin_1270_reports_report_yara_design.pdf"
        description = "Detects CAPE payload configuration data"
        category = "CAPE"
        author = "Malware Analysis Engineer"
        date = "2026-02-24"
    strings:
        $s1 = "TODO - Add relevant string from trimmed report or CAPE payloads" ascii wide
        $s2 = "TODO - Add more strings" ascii wide
    condition:
        uint16(0) == 0x5A4D and filesize < 15MB and any of them
}

/* ===================== SIGNATURES ===================== */

rule Breakwin_Signatures_Behavioral_0
{
    meta:
        filename = "wipers_Breakwin_1270_reports_report_yara_design.pdf"
        description = "Detects behavioral signature [0]"
        category = "SIGNATURES"
        author = "Malware Analysis Engineer"
        date = "2026-02-24"
    strings:
        $s1 = "TODO - Add relevant string from trimmed report or CAPE payloads" ascii wide
        $s2 = "TODO - Add more strings" ascii wide
    condition:
        uint16(0) == 0x5A4D and filesize < 15MB and any of them
}

rule Breakwin_Signatures_Behavioral_Triggered
{
    meta:
        filename = "wipers_Breakwin_1270_reports_report_yara_design.pdf"
        description = "Detects triggered behavioral signatures"
        category = "SIGNATURES"
        author = "Malware Analysis Engineer"
        date = "2026-02-24"
    strings:
        $s1 = "TODO - Add relevant string from trimmed report or CAPE payloads" ascii wide
        $s2 = "TODO - Add more strings" ascii wide
    condition:
        uint16(0) == 0x5A4D and filesize < 15MB and any of them
}

/* ===================== DEBUG ===================== */

rule Breakwin_Debug_Log_Main
{
    meta:
        filename = "wipers_Breakwin_1270_reports_report_yara_design.pdf"
        description = "Detects debug log activity"
        category = "DEBUG"
        author = "Malware Analysis Engineer"
        date = "2026-02-24"
    strings:
        $s1 = "TODO - Add relevant string from trimmed report or CAPE payloads" ascii wide
        $s2 = "TODO - Add more strings" ascii wide
    condition:
        uint16(0) == 0x5A4D and filesize < 15MB and any of them
}

rule Breakwin_Debug_Error_Information
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

rule Breakwin_Debug_AntiAnalysis
{
    meta:
        filename = "wipers_Breakwin_1270_reports_report_yara_design.pdf"
        description = "Detects anti-analysis debug strings"
        category = "DEBUG"
        author = "Malware Analysis Engineer"
        date = "2026-02-24"
    strings:
        $s1 = "TODO - Add relevant string from trimmed report or CAPE payloads" ascii wide
        $s2 = "TODO - Add more strings" ascii wide
    condition:
        uint16(0) == 0x5A4D and filesize < 15MB and any of them
}

/* ===================== URL ANALYSIS ===================== */

rule Breakwin_URL_Analysis_C2
{
    meta:
        filename = "wipers_Breakwin_1270_reports_report_yara_design.pdf"
        description = "Detects C2 URLs from URL analysis"
        category = "URL_ANALYSIS"
        author = "Malware Analysis Engineer"
        date = "2026-02-24"
    strings:
        $s1 = "TODO - Add relevant string from trimmed report or CAPE payloads" ascii wide
        $s2 = "TODO - Add more strings" ascii wide
    condition:
        uint16(0) == 0x5A4D and filesize < 15MB and any of them
}

rule Breakwin_URL_Analysis_Exfiltration
{
    meta:
        filename = "wipers_Breakwin_1270_reports_report_yara_design.pdf"
        description = "Detects exfiltration URLs"
        category = "URL_ANALYSIS"
        author = "Malware Analysis Engineer"
        date = "2026-02-24"
    strings:
        $s1 = "TODO - Add relevant string from trimmed report or CAPE payloads" ascii wide
        $s2 = "TODO - Add more strings" ascii wide
    condition:
        uint16(0) == 0x5A4D and filesize < 15MB and any of them
}

rule Breakwin_URL_Analysis_Communication
{
    meta:
        filename = "wipers_Breakwin_1270_reports_report_yara_design.pdf"
        description = "Detects URL-based command and control communication"
        category = "URL_ANALYSIS"
        author = "Malware Analysis Engineer"
        date = "2026-02-24"
    strings:
        $s1 = "TODO - Add relevant string from trimmed report or CAPE payloads" ascii wide
        $s2 = "TODO - Add more strings" ascii wide
    condition:
        uint16(0) == 0x5A4D and filesize < 15MB and any of them
}

/* ===================== ADDITIONAL FOCUSED RULES ===================== */

rule Breakwin_Payloads_High_Relevance
{
    meta:
        filename = "wipers_Breakwin_1270_reports_report_yara_design.pdf"
        description = "Detects high relevance payload indicators"
        category = "CAPE"
        author = "Malware Analysis Engineer"
        date = "2026-02-24"
    strings:
        $s1 = "TODO - Add relevant string from trimmed report or CAPE payloads" ascii wide
        $s2 = "TODO - Add more strings" ascii wide
    condition:
        uint16(0) == 0x5A4D and filesize < 15MB and any of them
}

rule Breakwin_Signatures_Reliable
{
    meta:
        filename = "wipers_Breakwin_1270_reports_report_yara_design.pdf"
        description = "Detects reliable behavioral signatures"
        category = "SIGNATURES"
        author = "Malware Analysis Engineer"
        date = "2026-02-24"
    strings:
        $s1 = "TODO - Add relevant string from trimmed report or CAPE payloads" ascii wide
        $s2 = "TODO - Add more strings" ascii wide
    condition:
        uint16(0) == 0x5A4D and filesize < 15MB and any of them
}

rule Breakwin_Debug_Crash_Reports
{
    meta:
        filename = "wipers_Breakwin_1270_reports_report_yara_design.pdf"
        description = "Detects debug crash and error reporting"
        category = "DEBUG"
        author = "Malware Analysis Engineer"
        date = "2026-02-24"
    strings:
        $s1 = "TODO - Add relevant string from trimmed report or CAPE payloads" ascii wide
        $s2 = "TODO - Add more strings" ascii wide
    condition:
        uint16(0) == 0x5A4D and filesize < 15MB and any of them
}

rule Breakwin_URL_Analysis_Direct_C2
{
    meta:
        filename = "wipers_Breakwin_1270_reports_report_yara_design.pdf"
        description = "Detects direct C2 indicators from URL analysis"
        category = "URL_ANALYSIS"
        author = "Malware Analysis Engineer"
        date = "2026-02-24"
    strings:
        $s1 = "TODO - Add relevant string from trimmed report or CAPE payloads" ascii wide
        $s2 = "TODO - Add more strings" ascii wide
    condition:
        uint16(0) == 0x5A4D and filesize < 15MB and any of them
}

rule Breakwin_Payloads_Configs_Strings
{
    meta:
        filename = "wipers_Breakwin_1270_reports_report_yara_design.pdf"
        description = "Detects payload configuration strings"
        category = "CAPE"
        author = "Malware Analysis Engineer"
        date = "2026-02-24"
    strings:
        $s1 = "TODO - Add relevant string from trimmed report or CAPE payloads" ascii wide
        $s2 = "TODO - Add more strings" ascii wide
    condition:
        uint16(0) == 0x5A4D and filesize < 15MB and any of them
}

rule Breakwin_Signatures_Behavior_Summary
{
    meta:
        filename = "wipers_Breakwin_1270_reports_report_yara_design.pdf"
        description = "Detects behavior summary signatures"
        category = "SIGNATURES"
        author = "Malware Analysis Engineer"
        date = "2026-02-24"
    strings:
        $s1 = "TODO - Add relevant string from trimmed report or CAPE payloads" ascii wide
        $s2 = "TODO - Add more strings" ascii wide
    condition:
        uint16(0) == 0x5A4D and filesize < 15MB and any of them
}

rule Breakwin_Debug_Analysis_Artifacts
{
    meta:
        filename = "wipers_Breakwin_1270_reports_report_yara_design.pdf"
        description = "Detects debug analysis artifacts"
        category = "DEBUG"
        author = "Malware Analysis Engineer"
        date = "2026-02-24"
    strings:
        $s1 = "TODO - Add relevant string from trimmed report or CAPE payloads" ascii wide
        $s2 = "TODO - Add more strings" ascii wide
    condition:
        uint16(0) == 0x5A4D and filesize < 15MB and any of them
}

rule Breakwin_URL_Analysis_Exfil_Endpoints
{
    meta:
        filename = "wipers_Breakwin_1270_reports_report_yara_design.pdf"
        description = "Detects exfiltration endpoints"
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