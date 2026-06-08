```
/*
YARA Rule Set for wipers_Breakwin_1271
Source: wipers_Breakwin_1271_reports_report_yara_design.pdf
All rules strictly adhere to YARA 3.6.0 syntax.
*/

import "pe"
import "math"

// ==================== CAPE Category Rules ====================

rule Breakwin_CAPE_Payloads_Detection
{
    meta:
        filename = "wipers_Breakwin_1271_reports_report_yara_design.pdf"
        description = "Detects unpacked payloads activity from CAPE report"
        category = "CAPE"
        author = "Malware Analysis Engineer"
        date = "2026-02-24"
    strings:
        $s1 = "TODO - Add relevant string from trimmed report or CAPE payloads" ascii wide
    condition:
        uint16(0) == 0x5A4D and filesize < 15MB and any of them
}

rule Breakwin_CAPE_Payloads_Config
{
    meta:
        filename = "wipers_Breakwin_1271_reports_report_yara_design.pdf"
        description = "Detects payload configuration indicators from CAPE"
        category = "CAPE"
        author = "Malware Analysis Engineer"
        date = "2026-02-24"
    strings:
        $s1 = "TODO - Add more strings" ascii wide
    condition:
        uint16(0) == 0x5A4D and filesize < 15MB and any of them
}

// ==================== SIGNATURES Category Rules ====================

rule Breakwin_Signatures_Behavioral_0
{
    meta:
        filename = "wipers_Breakwin_1271_reports_report_yara_design.pdf"
        description = "Detects behavioral signature activity from CAPE report"
        category = "SIGNATURES"
        author = "Malware Analysis Engineer"
        date = "2026-02-24"
    strings:
        $s1 = "TODO - Add relevant string from trimmed report or CAPE payloads" ascii wide
    condition:
        uint16(0) == 0x5A4D and filesize < 15MB and any of them
}

rule Breakwin_Signatures_Reliable_Triggers
{
    meta:
        filename = "wipers_Breakwin_1271_reports_report_yara_design.pdf"
        description = "Detects triggered behavioral signatures"
        category = "SIGNATURES"
        author = "Malware Analysis Engineer"
        date = "2026-02-24"
    strings:
        $s1 = "TODO - Add more strings" ascii wide
    condition:
        uint16(0) == 0x5A4D and filesize < 15MB and any of them
}

// ==================== DEBUG Category Rules ====================

rule Breakwin_Debug_Log_Activity
{
    meta:
        filename = "wipers_Breakwin_1271_reports_report_yara_design.pdf"
        description = "Detects debug and error log activity from CAPE report"
        category = "DEBUG"
        author = "Malware Analysis Engineer"
        date = "2026-02-24"
    strings:
        $s1 = "TODO - Add relevant string from trimmed report or CAPE payloads" ascii wide
    condition:
        uint16(0) == 0x5A4D and filesize < 15MB and any of them
}

rule Breakwin_Debug_Error_Information
{
    meta:
        filename = "wipers_Breakwin_1271_reports_report_yara_design.pdf"
        description = "Detects debug log and error information"
        category = "DEBUG"
        author = "Malware Analysis Engineer"
        date = "2026-02-24"
    strings:
        $s1 = "TODO - Add more strings" ascii wide
    condition:
        uint16(0) == 0x5A4D and filesize < 15MB and any of them
}

// ==================== URL_ANALYSIS Category Rules ====================

rule Breakwin_URL_Analysis_C2
{
    meta:
        filename = "wipers_Breakwin_1271_reports_report_yara_design.pdf"
        description = "Detects C2 or exfiltration URLs from URL analysis"
        category = "URL_ANALYSIS"
        author = "Malware Analysis Engineer"
        date = "2026-02-24"
    strings:
        $s1 = "TODO - Add relevant string from trimmed report or CAPE payloads" ascii wide
    condition:
        uint16(0) == 0x5A4D and filesize < 15MB and any of them
}

rule Breakwin_URL_Analysis_Exfiltration
{
    meta:
        filename = "wipers_Breakwin_1271_reports_report_yara_design.pdf"
        description = "Detects URL-based exfiltration indicators"
        category = "URL_ANALYSIS"
        author = "Malware Analysis Engineer"
        date = "2026-02-24"
    strings:
        $s1 = "TODO - Add more strings" ascii wide
    condition:
        uint16(0) == 0x5A4D and filesize < 15MB and any of them
}
```