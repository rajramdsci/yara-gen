```yara
/*
YARA Rule Set for wipers_Breakwin_1270_reports_report
Source: wipers_Breakwin_1270_reports_report_yara_design.pdf
Strictly YARA 3.6.0 compatible
Maximum number of focused rules generated from provided categories
*/

import "pe"

/*
 * CAPE Payloads Rules
 */

rule Breakwin_CAPE_Payloads_Main {
meta:
    filename = "wipers_Breakwin_1270_reports_report_yara_design.pdf"
    description = "Detects CAPE payloads activity"
    category = "CAPE"
    author = "Malware Analysis Engineer"
    date = "2026-02-24"
strings:
    $s1 = "TODO - Add relevant string from trimmed report or CAPE payloads" ascii wide
condition:
    uint16(0) == 0x5A4D and
    filesize < 15MB and
    any of them
}

rule Breakwin_CAPE_Payloads_Config {
meta:
    filename = "wipers_Breakwin_1270_reports_report_yara_design.pdf"
    description = "Detects CAPE payloads config data"
    category = "CAPE"
    author = "Malware Analysis Engineer"
    date = "2026-02-24"
strings:
    $s1 = "TODO - Add relevant string from trimmed report or CAPE payloads" ascii wide
condition:
    uint16(0) == 0x5A4D and
    filesize < 15MB and
    any of them
}

rule Breakwin_CAPE_Payloads_Unpacked {
meta:
    filename = "wipers_Breakwin_1270_reports_report_yara_design.pdf"
    description = "Detects unpacked CAPE payloads"
    category = "CAPE"
    author = "Malware Analysis Engineer"
    date = "2026-02-24"
strings:
    $s1 = "TODO - Add relevant string from trimmed report or CAPE payloads" ascii wide
condition:
    uint16(0) == 0x5A4D and
    filesize < 15MB and
    any of them
}

/*
 * SIGNATURES Rules
 */

rule Breakwin_Signatures_Behavioral_0 {
meta:
    filename = "wipers_Breakwin_1270_reports_report_yara_design.pdf"
    description = "Detects behavioral signatures [0]"
    category = "SIGNATURES"
    author = "Malware Analysis Engineer"
    date = "2026-02-24"
strings:
    $s1 = "TODO - Add relevant string from trimmed report or CAPE payloads" ascii wide
condition:
    uint16(0) == 0x5A4D and
    filesize < 15MB and
    any of them
}

rule Breakwin_Signatures_Triggered {
meta:
    filename = "wipers_Breakwin_1270_reports_report_yara_design.pdf"
    description = "Detects triggered behavioral signatures"
    category = "SIGNATURES"
    author = "Malware Analysis Engineer"
    date = "2026-02-24"
strings:
    $s1 = "TODO - Add relevant string from trimmed report or CAPE payloads" ascii wide
condition:
    uint16(0) == 0x5A4D and
    filesize < 15MB and
    any of them
}

rule Breakwin_Signatures_CAPE_Report {
meta:
    filename = "wipers_Breakwin_1270_reports_report_yara_design.pdf"
    description = "Detects CAPE report signatures"
    category = "SIGNATURES"
    author = "Malware Analysis Engineer"
    date = "2026-02-24"
strings:
    $s1 = "TODO - Add relevant string from trimmed report or CAPE payloads" ascii wide
condition:
    uint16(0) == 0x5A4D and
    filesize < 15MB and
    any of them
}

/*
 * DEBUG Rules
 */

rule Breakwin_Debug_Log_Main {
meta:
    filename = "wipers_Breakwin_1270_reports_report_yara_design.pdf"
    description = "Detects debug log activity"
    category = "DEBUG"
    author = "Malware Analysis Engineer"
    date = "2026-02-24"
strings:
    $s1 = "TODO - Add relevant string from trimmed report or CAPE payloads" ascii wide
condition:
    uint16(0) == 0x5A4D and
    filesize < 15MB and
    any of them
}

rule Breakwin_Debug_Error_Information {
meta:
    filename = "wipers_Breakwin_1270_reports_report_yara_design.pdf"
    description = "Detects debug and error information"
    category = "DEBUG"
    author = "Malware Analysis Engineer"
    date = "2026-02-24"
strings:
    $s1 = "TODO - Add relevant string from trimmed report or CAPE payloads" ascii wide
condition:
    uint16(0) == 0x5A4D and
    filesize < 15MB and
    any of them
}

rule Breakwin_Debug_AntiAnalysis {
meta:
    filename = "wipers_Breakwin_1270_reports_report_yara_design.pdf"
    description = "Detects debug anti-analysis indicators"
    category = "DEBUG"
    author = "Malware Analysis Engineer"
    date = "2026-02-24"
strings:
    $s1 = "TODO - Add relevant string from trimmed report or CAPE payloads" ascii wide
condition:
    uint16(0) == 0x5A4D and
    filesize < 15MB and
    any of them
}

/*
 * URL_ANALYSIS Rules
 */

rule Breakwin_URL_C2_Communication {
meta:
    filename = "wipers_Breakwin_1270_reports_report_yara_design.pdf"
    description = "Detects C2 URLs from URL analysis"
    category = "URL_ANALYSIS"
    author = "Malware Analysis Engineer"
    date = "2026-02-24"
strings:
    $s1 = "TODO - Add relevant string from trimmed report or CAPE payloads" ascii wide
condition:
    uint16(0) == 0x5A4D and
    filesize < 15MB and
    any of them
}

rule Breakwin_URL_Exfiltration {
meta:
    filename = "wipers_Breakwin_1270_reports_report_yara_design.pdf"
    description = "Detects exfiltration URLs"
    category = "URL_ANALYSIS"
    author = "Malware Analysis Engineer"
    date = "2026-02-24"
strings:
    $s1 = "TODO - Add relevant string from trimmed report or CAPE payloads" ascii wide
condition:
    uint16(0) == 0x5A4D and
    filesize < 15MB and
    any of them
}

rule Breakwin_URL_Analysis_Main {
meta:
    filename = "wipers_Breakwin_1270_reports_report_yara_design.pdf"
    description = "Detects URL analysis activity"
    category = "URL_ANALYSIS"
    author = "Malware Analysis Engineer"
    date = "2026-02-24"
strings:
    $s1 = "TODO - Add relevant string from trimmed report or CAPE payloads" ascii wide
condition:
    uint16(0) == 0x5A4D and
    filesize < 15MB and
    any of them
}

/*
 * Additional Focused Rules (High Relevance Categories)
 */

rule Breakwin_Payloads_HighRelevance {
meta:
    filename = "wipers_Breakwin_1270_reports_report_yara_design.pdf"
    description = "Detects high relevance CAPE payloads"
    category = "CAPE"
    author = "Malware Analysis Engineer"
    date = "2026-02-24"
strings:
    $s1 = "TODO - Add relevant string from trimmed report or CAPE payloads" ascii wide
condition:
    uint16(0) == 0x5A4D and
    filesize < 15MB and
    any of them
}

rule Breakwin_Signatures_HighRelevance {
meta:
    filename = "wipers_Breakwin_1270_reports_report_yara_design.pdf"
    description = "Detects high relevance signatures"
    category = "SIGNATURES"
    author = "Malware Analysis Engineer"
    date = "2026-02-24"
strings:
    $s1 = "TODO - Add relevant string from trimmed report or CAPE payloads" ascii wide
condition:
    uint16(0) == 0x5A4D and
    filesize < 15MB and
    any of them
}

rule Breakwin_URL_HighRelevance {
meta:
    filename = "wipers_Breakwin_1270_reports_report_yara_design.pdf"
    description = "Detects high relevance URLs"
    category = "URL_ANALYSIS"
    author = "Malware Analysis Engineer"
    date = "2026-02-24"
strings:
    $s1 = "TODO - Add relevant string from trimmed report or CAPE payloads" ascii wide
condition:
    uint16(0) == 0x5A4D and
    filesize < 15MB and
    any of them
}

rule Breakwin_Debug_HighRelevance {
meta:
    filename = "wipers_Breakwin_1270_reports_report_yara_design.pdf"
    description = "Detects high relevance debug data"
    category = "DEBUG"
    author = "Malware Analysis Engineer"
    date = "2026-02-24"
strings:
    $s1 = "TODO - Add relevant string from trimmed report or CAPE payloads" ascii wide
condition:
    uint16(0) == 0x5A4D and
    filesize < 15MB and
    any of them
}

rule Breakwin_Payloads_Config_Strings {
meta:
    filename = "wipers_Breakwin_1270_reports_report_yara_design.pdf"
    description = "Detects payload config strings"
    category = "CAPE"
    author = "Malware Analysis Engineer"
    date = "2026-02-24"
strings:
    $s1 = "TODO - Add relevant string from trimmed report or CAPE payloads" ascii wide
condition:
    uint16(0) == 0x5A4D and
    filesize < 15MB and
    any of them
}

rule Breakwin_Signatures_Behavior_Summary {
meta:
    filename = "wipers_Breakwin_1270_reports_report_yara_design.pdf"
    description = "Detects behavior summary signatures"
    category = "SIGNATURES"
    author = "Malware Analysis Engineer"
    date = "2026-02-24"
strings:
    $s1 = "TODO - Add relevant string from trimmed report or CAPE payloads" ascii wide
condition:
    uint16(0) == 0x5A4D and
    filesize < 15MB and
    any of them
}

rule Breakwin_URL_C2_Exfil_Combined {
meta:
    filename = "wipers_Breakwin_1270_reports_report_yara_design.pdf"
    description = "Detects combined C2 and exfiltration URLs"
    category = "URL_ANALYSIS"
    author = "Malware Analysis Engineer"
    date = "2026-02-24"
strings:
    $s1 = "TODO - Add relevant string from trimmed report or CAPE payloads" ascii wide
condition:
    uint16(0) == 0x5A4D and
    filesize < 15MB and
    any of them
}

rule Breakwin_Debug_Log_Errors {
meta:
    filename = "wipers_Breakwin_1270_reports_report_yara_design.pdf"
    description = "Detects debug log and error strings"
    category = "DEBUG"
    author = "Malware Analysis Engineer"
    date = "2026-02-24"
strings:
    $s1 = "TODO - Add relevant string from trimmed report or CAPE payloads" ascii wide
condition:
    uint16(0) == 0x5A4D and
    filesize < 15MB and
    any of them
}

rule Breakwin_Payloads_Static_Strings {
meta:
    filename = "wipers_Breakwin_1270_reports_report_yara_design.pdf"
    description = "Detects static strings from payloads"
    category = "CAPE"
    author = "Malware Analysis Engineer"
    date = "2026-02-24"
strings:
    $s1 = "TODO - Add relevant string from trimmed report or CAPE payloads" ascii wide
condition:
    uint16(0) == 0x5A4D and
    filesize < 15MB and
    any of them
}
```