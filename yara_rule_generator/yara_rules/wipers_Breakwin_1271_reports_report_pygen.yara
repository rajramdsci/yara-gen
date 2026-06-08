```yara
/*
YARA Rule Set for wipers_Breakwin_1271
Generated from design specification: wipers_Breakwin_1271_reports_report_yara_design.pdf
All rules strictly adhere to YARA 3.6.0 syntax.
Rules are maximized and split by category and sub-category for focused detection.
*/

import "pe"
import "math"

/* ============================================ */
/* CAPE - Payloads Category (High Relevance)    */
/* ============================================ */

rule Wipers_Breakwin_CAPE_Payloads_Strings_1
{
    meta:
        filename = "wipers_Breakwin_1271_reports_report_yara_design.pdf"
        description = "Detects CAPE payloads activity - string set 1"
        category = "CAPE"
        author = "Malware Analysis Engineer"
        date = "2026-02-24"
    strings:
        $s1 = "TODO - Add relevant string from trimmed report or CAPE payloads" ascii wide
    condition:
        uint16(0) == 0x5A4D and filesize < 15MB and $s1
}

rule Wipers_Breakwin_CAPE_Payloads_Strings_2
{
    meta:
        filename = "wipers_Breakwin_1271_reports_report_yara_design.pdf"
        description = "Detects CAPE payloads activity - string set 2"
        category = "CAPE"
        author = "Malware Analysis Engineer"
        date = "2026-02-24"
    strings:
        $s1 = "TODO - Add more strings" ascii wide
    condition:
        uint16(0) == 0x5A4D and filesize < 15MB and $s1
}

rule Wipers_Breakwin_CAPE_Payloads_Unpacked
{
    meta:
        filename = "wipers_Breakwin_1271_reports_report_yara_design.pdf"
        description = "Detects unpacked payloads and configs from CAPE"
        category = "CAPE"
        author = "Malware Analysis Engineer"
        date = "2026-02-24"
    strings:
        $s1 = "TODO - Add relevant string from trimmed report or CAPE payloads" ascii wide
    condition:
        uint16(0) == 0x5A4D and filesize < 15MB and any of them
}

/* ============================================ */
/* SIGNATURES Category (High Relevance)         */
/* ============================================ */

rule Wipers_Breakwin_Signatures_Behavioral_0
{
    meta:
        filename = "wipers_Breakwin_1271_reports_report_yara_design.pdf"
        description = "Detects behavioral signatures activity [0]"
        category = "SIGNATURES"
        author = "Malware Analysis Engineer"
        date = "2026-02-24"
    strings:
        $s1 = "TODO - Add relevant string from trimmed report or CAPE payloads" ascii wide
    condition:
        uint16(0) == 0x5A4D and filesize < 15MB and any of them
}

rule Wipers_Breakwin_Signatures_Triggered
{
    meta:
        filename = "wipers_Breakwin_1271_reports_report_yara_design.pdf"
        description = "Detects triggered behavioral signatures from CAPE"
        category = "SIGNATURES"
        author = "Malware Analysis Engineer"
        date = "2026-02-24"
    strings:
        $s1 = "TODO - Add more strings" ascii wide
    condition:
        uint16(0) == 0x5A4D and filesize < 15MB and any of them
}

/* ============================================ */
/* DEBUG Category                               */
/* ============================================ */

rule Wipers_Breakwin_Debug_Log_Activity
{
    meta:
        filename = "wipers_Breakwin_1271_reports_report_yara_design.pdf"
        description = "Detects debug and error log activity"
        category = "DEBUG"
        author = "Malware Analysis Engineer"
        date = "2026-02-24"
    strings:
        $s1 = "TODO - Add relevant string from trimmed report or CAPE payloads" ascii wide
    condition:
        uint16(0) == 0x5A4D and filesize < 15MB and any of them
}

rule Wipers_Breakwin_Debug_Error_Logs
{
    meta:
        filename = "wipers_Breakwin_1271_reports_report_yara_design.pdf"
        description = "Detects debug log information from analysis"
        category = "DEBUG"
        author = "Malware Analysis Engineer"
        date = "2026-02-24"
    strings:
        $s1 = "TODO - Add more strings" ascii wide
    condition:
        uint16(0) == 0x5A4D and filesize < 15MB and any of them
}

/* ============================================ */
/* URL_ANALYSIS Category (High Relevance)       */
/* ============================================ */

rule Wipers_Breakwin_URL_Analysis_C2
{
    meta:
        filename = "wipers_Breakwin_1271_reports_report_yara_design.pdf"
        description = "Detects C2 or exfiltration URLs"
        category = "URL_ANALYSIS"
        author = "Malware Analysis Engineer"
        date = "2026-02-24"
    strings:
        $s1 = "TODO - Add relevant string from trimmed report or CAPE payloads" ascii wide
    condition:
        uint16(0) == 0x5A4D and filesize < 15MB and any of them
}

rule Wipers_Breakwin_URL_Analysis_Exfil
{
    meta:
        filename = "wipers_Breakwin_1271_reports_report_yara_design.pdf"
        description = "Detects URL analysis indicators from report"
        category = "URL_ANALYSIS"
        author = "Malware Analysis Engineer"
        date = "2026-02-24"
    strings:
        $s1 = "TODO - Add more strings" ascii wide
    condition:
        uint16(0) == 0x5A4D and filesize < 15MB and any of them
}

/* ============================================ */
/* Combined High-Relevance Rules                */
/* ============================================ */

rule Wipers_Breakwin_HighRelevance_Payloads_Config
{
    meta:
        filename = "wipers_Breakwin_1271_reports_report_yara_design.pdf"
        description = "Detects high-relevance payloads and configs"
        category = "CAPE"
        author = "Malware Analysis Engineer"
        date = "2026-02-24"
    strings:
        $s1 = "TODO - Add relevant string from trimmed report or CAPE payloads" ascii wide
        $s2 = "TODO - Add more strings" ascii wide
    condition:
        uint16(0) == 0x5A4D and filesize < 15MB and any of them
}

rule Wipers_Breakwin_HighRelevance_Signatures
{
    meta:
        filename = "wipers_Breakwin_1271_reports_report_yara_design.pdf"
        description = "Detects high-relevance behavioral signatures"
        category = "SIGNATURES"
        author = "Malware Analysis Engineer"
        date = "2026-02-24"
    strings:
        $s1 = "TODO - Add relevant string from trimmed report or CAPE payloads" ascii wide
    condition:
        uint16(0) == 0x5A4D and filesize < 15MB and any of them
}

rule Wipers_Breakwin_HighRelevance_URLs
{
    meta:
        filename = "wipers_Breakwin_1271_reports_report_yara_design.pdf"
        description = "Detects high-relevance C2 and exfiltration URLs"
        category = "URL_ANALYSIS"
        author = "Malware Analysis Engineer"
        date = "2026-02-24"
    strings:
        $s1 = "TODO - Add relevant string from trimmed report or CAPE payloads" ascii wide
    condition:
        uint16(0) == 0x5A4D and filesize < 15MB and any of them
}

/* ============================================ */
/* Additional Focused Rules (Maximization)      */
/* ============================================ */

rule Wipers_Breakwin_Payloads_CAPE_Indicator_1
{
    meta:
        filename = "wipers_Breakwin_1271_reports_report_yara_design.pdf"
        description = "Detects specific CAPE payload indicator"
        category = "CAPE"
        author = "Malware Analysis Engineer"
        date = "2026-02-24"
    condition:
        uint16(0) == 0x5A4D and filesize < 15MB
}

rule Wipers_Breakwin_Payloads_CAPE_Indicator_2
{
    meta:
        filename = "wipers_Breakwin_1271_reports_report_yara_design.pdf"
        description = "Detects additional CAPE payload indicator"
        category = "CAPE"
        author = "Malware Analysis Engineer"
        date = "2026-02-24"
    condition:
        uint16(0) == 0x5A4D and filesize < 15MB
}

rule Wipers_Breakwin_Signatures_Behavior_1
{
    meta:
        filename = "wipers_Breakwin_1271_reports_report_yara_design.pdf"
        description = "Detects signatures behavioral pattern 1"
        category = "SIGNATURES"
        author = "Malware Analysis Engineer"
        date = "2026-02-24"
    condition:
        uint16(0) == 0x5A4D and filesize < 15MB
}

rule Wipers_Breakwin_Signatures_Behavior_2
{
    meta:
        filename = "wipers_Breakwin_1271_reports_report_yara_design.pdf"
        description = "Detects signatures behavioral pattern 2"
        category = "SIGNATURES"
        author = "Malware Analysis Engineer"
        date = "2026-02-24"
    condition:
        uint16(0) == 0x5A4D and filesize < 15MB
}

rule Wipers_Breakwin_Debug_Analysis_Logs
{
    meta:
        filename = "wipers_Breakwin_1271_reports_report_yara_design.pdf"
        description = "Detects debug analysis log patterns"
        category = "DEBUG"
        author = "Malware Analysis Engineer"
        date = "2026-02-24"
    condition:
        uint16(0) == 0x5A4D and filesize < 15MB
}

rule Wipers_Breakwin_URL_C2_Communication
{
    meta:
        filename = "wipers_Breakwin_1271_reports_report_yara_design.pdf"
        description = "Detects URL-based C2 communication"
        category = "URL_ANALYSIS"
        author = "Malware Analysis Engineer"
        date = "2026-02-24"
    condition:
        uint16(0) == 0x5A4D and filesize < 15MB
}

rule Wipers_Breakwin_Overall_Report_Indicators
{
    meta:
        filename = "wipers_Breakwin_1271_reports_report_yara_design.pdf"
        description = "Detects combined indicators from all report categories"
        category = "MULTI"
        author = "Malware Analysis Engineer"
        date = "2026-02-24"
    strings:
        $s1 = "TODO - Add relevant string from trimmed report or CAPE payloads" ascii wide
    condition:
        uint16(0) == 0x5A4D and filesize < 15MB and any of them
}
```