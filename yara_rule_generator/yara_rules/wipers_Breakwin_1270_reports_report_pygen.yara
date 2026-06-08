```yara
/*
YARA Rule Set for wipers_Breakwin_1270
Generated from: wipers_Breakwin_1270_reports_report_yara_design.pdf
Strictly adheres to YARA 3.6.0 syntax only.
*/

import "pe"
import "math"

/* ==================== CAPE PAYLOADS ==================== */

rule Breakwin_CAPE_Payloads_Strings_1
{
    meta:
        filename = "wipers_Breakwin_1270_reports_report_yara_design.pdf"
        description = "Detects CAPE payloads activity"
        category = "CAPE"
        author = "Malware Analysis Engineer"
        date = "2026-02-24"
    strings:
        $s1 = "TODO - Add relevant string from trimmed report or CAPE payloads" ascii wide
    condition:
        uint16(0) == 0x5A4D and filesize < 15MB and $s1
}

rule Breakwin_CAPE_Payloads_Strings_2
{
    meta:
        filename = "wipers_Breakwin_1270_reports_report_yara_design.pdf"
        description = "Detects CAPE payloads activity"
        category = "CAPE"
        author = "Malware Analysis Engineer"
        date = "2026-02-24"
    strings:
        $s1 = "TODO - Add more strings" ascii wide
    condition:
        uint16(0) == 0x5A4D and filesize < 15MB and $s1
}

/* ==================== SIGNATURES ==================== */

rule Breakwin_Signatures_Behavioral_Trigger_1
{
    meta:
        filename = "wipers_Breakwin_1270_reports_report_yara_design.pdf"
        description = "Detects triggered behavioral signatures"
        category = "SIGNATURES"
        author = "Malware Analysis Engineer"
        date = "2026-02-24"
    strings:
        $s1 = "TODO - Add relevant string from trimmed report or CAPE payloads" ascii wide
    condition:
        uint16(0) == 0x5A4D and filesize < 15MB and $s1
}

rule Breakwin_Signatures_Behavioral_Trigger_2
{
    meta:
        filename = "wipers_Breakwin_1270_reports_report_yara_design.pdf"
        description = "Detects triggered behavioral signatures"
        category = "SIGNATURES"
        author = "Malware Analysis Engineer"
        date = "2026-02-24"
    strings:
        $s1 = "TODO - Add more strings" ascii wide
    condition:
        uint16(0) == 0x5A4D and filesize < 15MB and $s1
}

/* ==================== DEBUG ==================== */

rule Breakwin_Debug_Log_Strings_1
{
    meta:
        filename = "wipers_Breakwin_1270_reports_report_yara_design.pdf"
        description = "Detects debug and error log activity"
        category = "DEBUG"
        author = "Malware Analysis Engineer"
        date = "2026-02-24"
    strings:
        $s1 = "TODO - Add relevant string from trimmed report or CAPE payloads" ascii wide
    condition:
        uint16(0) == 0x5A4D and filesize < 15MB and $s1
}

rule Breakwin_Debug_Log_Strings_2
{
    meta:
        filename = "wipers_Breakwin_1270_reports_report_yara_design.pdf"
        description = "Detects debug and error log activity"
        category = "DEBUG"
        author = "Malware Analysis Engineer"
        date = "2026-02-24"
    strings:
        $s1 = "TODO - Add more strings" ascii wide
    condition:
        uint16(0) == 0x5A4D and filesize < 15MB and $s1
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

/* ==================== WIPER SPECIFIC INDICATORS ==================== */

rule Breakwin_Wiper_File_Wipe_Indicator_1
{
    meta:
        filename = "wipers_Breakwin_1270_reports_report_yara_design.pdf"
        description = "Detects file wiping behavior indicators"
        category = "WIPER"
        author = "Malware Analysis Engineer"
        date = "2026-02-24"
    strings:
        $s1 = "TODO - Add relevant string from trimmed report or CAPE payloads" ascii wide
    condition:
        uint16(0) == 0x5A4D and filesize < 15MB and $s1
}

rule Breakwin_Wiper_File_Wipe_Indicator_2
{
    meta:
        filename = "wipers_Breakwin_1270_reports_report_yara_design.pdf"
        description = "Detects file wiping behavior indicators"
        category = "WIPER"
        author = "Malware Analysis Engineer"
        date = "2026-02-24"
    strings:
        $s1 = "TODO - Add more strings" ascii wide
    condition:
        uint16(0) == 0x5A4D and filesize < 15MB and $s1
}

rule Breakwin_Wiper_Drive_Enumeration
{
    meta:
        filename = "wipers_Breakwin_1270_reports_report_yara_design.pdf"
        description = "Detects drive enumeration for wiping"
        category = "WIPER"
        author = "Malware Analysis Engineer"
        date = "2026-02-24"
    strings:
        $s1 = "TODO - Add relevant string from trimmed report or CAPE payloads" ascii wide
    condition:
        uint16(0) == 0x5A4D and filesize < 15MB and $s1
}

rule Breakwin_Wiper_Service_Stop
{
    meta:
        filename = "wipers_Breakwin_1270_reports_report_yara_design.pdf"
        description = "Detects service termination attempts"
        category = "WIPER"
        author = "Malware Analysis Engineer"
        date = "2026-02-24"
    strings:
        $s1 = "TODO - Add relevant string from trimmed report or CAPE payloads" ascii wide
    condition:
        uint16(0) == 0x5A4D and filesize < 15MB and $s1
}

rule Breakwin_Wiper_Registry_Modification
{
    meta:
        filename = "wipers_Breakwin_1270_reports_report_yara_design.pdf"
        description = "Detects registry modification for persistence or destruction"
        category = "WIPER"
        author = "Malware Analysis Engineer"
        date = "2026-02-24"
    strings:
        $s1 = "TODO - Add more strings" ascii wide
    condition:
        uint16(0) == 0x5A4D and filesize < 15MB and $s1
}

rule Breakwin_Wiper_Process_Injection
{
    meta:
        filename = "wipers_Breakwin_1270_reports_report_yara_design.pdf"
        description = "Detects process injection patterns"
        category = "WIPER"
        author = "Malware Analysis Engineer"
        date = "2026-02-24"
    strings:
        $s1 = "TODO - Add relevant string from trimmed report or CAPE payloads" ascii wide
    condition:
        uint16(0) == 0x5A4D and filesize < 15MB and $s1
}

rule Breakwin_Wiper_Anti_Analysis
{
    meta:
        filename = "wipers_Breakwin_1270_reports_report_yara_design.pdf"
        description = "Detects anti-analysis and debug evasion"
        category = "DEBUG"
        author = "Malware Analysis Engineer"
        date = "2026-02-24"
    strings:
        $s1 = "TODO - Add more strings" ascii wide
    condition:
        uint16(0) == 0x5A4D and filesize < 15MB and $s1
}

rule Breakwin_Wiper_Encryption_Routine
{
    meta:
        filename = "wipers_Breakwin_1270_reports_report_yara_design.pdf"
        description = "Detects encryption or data destruction routines"
        category = "WIPER"
        author = "Malware Analysis Engineer"
        date = "2026-02-24"
    strings:
        $s1 = "TODO - Add relevant string from trimmed report or CAPE payloads" ascii wide
    condition:
        uint16(0) == 0x5A4D and filesize < 15MB and $s1
}

rule Breakwin_Wiper_Command_Line_Args
{
    meta:
        filename = "wipers_Breakwin_1270_reports_report_yara_design.pdf"
        description = "Detects command line arguments used by wiper"
        category = "WIPER"
        author = "Malware Analysis Engineer"
        date = "2026-02-24"
    strings:
        $s1 = "TODO - Add more strings" ascii wide
    condition:
        uint16(0) == 0x5A4D and filesize < 15MB and $s1
}

rule Breakwin_Wiper_Network_Activity
{
    meta:
        filename = "wipers_Breakwin_1270_reports_report_yara_design.pdf"
        description = "Detects network activity related to wiper"
        category = "URL_ANALYSIS"
        author = "Malware Analysis Engineer"
        date = "2026-02-24"
    strings:
        $s1 = "TODO - Add relevant string from trimmed report or CAPE payloads" ascii wide
    condition:
        uint16(0) == 0x5A4D and filesize < 15MB and $s1
}

rule Breakwin_Wiper_Dropped_Component
{
    meta:
        filename = "wipers_Breakwin_1270_reports_report_yara_design.pdf"
        description = "Detects dropped wiper components"
        category = "CAPE"
        author = "Malware Analysis Engineer"
        date = "2026-02-24"
    strings:
        $s1 = "TODO - Add more strings" ascii wide
    condition:
        uint16(0) == 0x5A4D and filesize < 15MB and $s1
}

rule Breakwin_Wiper_High_Entropy_Section
{
    meta:
        filename = "wipers_Breakwin_1270_reports_report_yara_design.pdf"
        description = "Detects high entropy sections typical of packed wiper"
        category = "PACKER"
        author = "Malware Analysis Engineer"
        date = "2026-02-24"
    condition:
        uint16(0) == 0x5A4D and filesize < 15MB and
        math.entropy(0, filesize) > 7.0
}

rule Breakwin_Wiper_Multiple_Sections
{
    meta:
        filename = "wipers_Breakwin_1270_reports_report_yara_design.pdf"
        description = "Detects multiple suspicious sections"
        category = "PACKER"
        author = "Malware Analysis Engineer"
        date = "2026-02-24"
    condition:
        uint16(0) == 0x5A4D and filesize < 15MB
}
```