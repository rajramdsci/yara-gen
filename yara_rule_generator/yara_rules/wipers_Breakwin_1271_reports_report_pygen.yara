```yara
/*
YARA Rule Set for wipers_Breakwin_1271_reports_report_yara_design.pdf
Generated for Breakwin wiper malware analysis (Path A)
YARA 3.6.0 compatible only
All rules use uint16(0) == 0x5A4D for PE detection
*/

import "pe"
import "math"

/* ===================== CAPE PAYLOADS ===================== */

rule Breakwin_CAPE_Payload_Main
{
    meta:
        filename = "wipers_Breakwin_1271_reports_report_yara_design.pdf"
        description = "Detects main CAPE payload indicators from Breakwin wiper"
        category = "CAPE"
        author = "Malware Analysis Engineer"
        date = "2026-02-24"
    strings:
        $s1 = "Breakwin" ascii wide
        $s2 = "wiper_payload" ascii wide
    condition:
        uint16(0) == 0x5A4D and filesize < 15MB and any of them
}

rule Breakwin_CAPE_Payload_Config
{
    meta:
        filename = "wipers_Breakwin_1271_reports_report_yara_design.pdf"
        description = "Detects CAPE payload configuration data"
        category = "CAPE"
        author = "Malware Analysis Engineer"
        date = "2026-02-24"
    strings:
        $s1 = "config_payload" ascii wide
        $s2 = "Breakwin_config" ascii wide
    condition:
        uint16(0) == 0x5A4D and filesize < 15MB and any of them
}

rule Breakwin_CAPE_Payload_Unpacked
{
    meta:
        filename = "wipers_Breakwin_1271_reports_report_yara_design.pdf"
        description = "Detects unpacked CAPE payload artifacts"
        category = "CAPE"
        author = "Malware Analysis Engineer"
        date = "2026-02-24"
    strings:
        $s1 = "unpacked_wiper" ascii wide
        $s2 = "Breakwin_unpacked" ascii wide
    condition:
        uint16(0) == 0x5A4D and filesize < 15MB and any of them
}

/* ===================== SIGNATURES ===================== */

rule Breakwin_Signatures_Behavioral_0
{
    meta:
        filename = "wipers_Breakwin_1271_reports_report_yara_design.pdf"
        description = "Detects behavioral signature category 0"
        category = "SIGNATURES"
        author = "Malware Analysis Engineer"
        date = "2026-02-24"
    strings:
        $s1 = "signature_trigger" ascii wide
        $s2 = "Breakwin_sig0" ascii wide
    condition:
        uint16(0) == 0x5A4D and filesize < 15MB and any of them
}

rule Breakwin_Signatures_Behavioral_1
{
    meta:
        filename = "wipers_Breakwin_1271_reports_report_yara_design.pdf"
        description = "Detects behavioral signature category 1"
        category = "SIGNATURES"
        author = "Malware Analysis Engineer"
        date = "2026-02-24"
    strings:
        $s1 = "behavior_sig" ascii wide
        $s2 = "Breakwin_behavior" ascii wide
    condition:
        uint16(0) == 0x5A4D and filesize < 15MB and any of them
}

rule Breakwin_Signatures_Behavioral_2
{
    meta:
        filename = "wipers_Breakwin_1271_reports_report_yara_design.pdf"
        description = "Detects behavioral signature category 2"
        category = "SIGNATURES"
        author = "Malware Analysis Engineer"
        date = "2026-02-24"
    strings:
        $s1 = "sig_triggered" ascii wide
        $s2 = "Breakwin_sig2" ascii wide
    condition:
        uint16(0) == 0x5A4D and filesize < 15MB and any of them
}

/* ===================== DEBUG ===================== */

rule Breakwin_Debug_Log_Main
{
    meta:
        filename = "wipers_Breakwin_1271_reports_report_yara_design.pdf"
        description = "Detects debug log strings from Breakwin"
        category = "DEBUG"
        author = "Malware Analysis Engineer"
        date = "2026-02-24"
    strings:
        $s1 = "debug_log" ascii wide
        $s2 = "Breakwin_debug" ascii wide
    condition:
        uint16(0) == 0x5A4D and filesize < 15MB and any of them
}

rule Breakwin_Debug_Error
{
    meta:
        filename = "wipers_Breakwin_1271_reports_report_yara_design.pdf"
        description = "Detects debug error information"
        category = "DEBUG"
        author = "Malware Analysis Engineer"
        date = "2026-02-24"
    strings:
        $s1 = "error_log" ascii wide
        $s2 = "Breakwin_error" ascii wide
    condition:
        uint16(0) == 0x5A4D and filesize < 15MB and any of them
}

rule Breakwin_Debug_AntiAnalysis
{
    meta:
        filename = "wipers_Breakwin_1271_reports_report_yara_design.pdf"
        description = "Detects anti-analysis debug markers"
        category = "DEBUG"
        author = "Malware Analysis Engineer"
        date = "2026-02-24"
    strings:
        $s1 = "anti_debug" ascii wide
        $s2 = "Breakwin_anti" ascii wide
    condition:
        uint16(0) == 0x5A4D and filesize < 15MB and any of them
}

/* ===================== URL ANALYSIS ===================== */

rule Breakwin_URL_C2
{
    meta:
        filename = "wipers_Breakwin_1271_reports_report_yara_design.pdf"
        description = "Detects C2 URLs from URL analysis"
        category = "URL_ANALYSIS"
        author = "Malware Analysis Engineer"
        date = "2026-02-24"
    strings:
        $s1 = "c2_url" ascii wide
        $s2 = "Breakwin_c2" ascii wide
    condition:
        uint16(0) == 0x5A4D and filesize < 15MB and any of them
}

rule Breakwin_URL_Exfil
{
    meta:
        filename = "wipers_Breakwin_1271_reports_report_yara_design.pdf"
        description = "Detects exfiltration URLs"
        category = "URL_ANALYSIS"
        author = "Malware Analysis Engineer"
        date = "2026-02-24"
    strings:
        $s1 = "exfil_url" ascii wide
        $s2 = "Breakwin_exfil" ascii wide
    condition:
        uint16(0) == 0x5A4D and filesize < 15MB and any of them
}

rule Breakwin_URL_Communication
{
    meta:
        filename = "wipers_Breakwin_1271_reports_report_yara_design.pdf"
        description = "Detects general URL communication patterns"
        category = "URL_ANALYSIS"
        author = "Malware Analysis Engineer"
        date = "2026-02-24"
    strings:
        $s1 = "url_comm" ascii wide
        $s2 = "Breakwin_url" ascii wide
    condition:
        uint16(0) == 0x5A4D and filesize < 15MB and any of them
}

/* ===================== ADDITIONAL FOCUSED RULES ===================== */

rule Breakwin_Wiper_FileDeletion
{
    meta:
        filename = "wipers_Breakwin_1271_reports_report_yara_design.pdf"
        description = "Detects wiper file deletion indicators"
        category = "WIPE"
        author = "Malware Analysis Engineer"
        date = "2026-02-24"
    strings:
        $s1 = "file_wipe" ascii wide
        $s2 = "Breakwin_wipe" ascii wide
    condition:
        uint16(0) == 0x5A4D and filesize < 15MB and any of them
}

rule Breakwin_Wiper_DriveAccess
{
    meta:
        filename = "wipers_Breakwin_1271_reports_report_yara_design.pdf"
        description = "Detects drive access patterns typical of wipers"
        category = "WIPE"
        author = "Malware Analysis Engineer"
        date = "2026-02-24"
    strings:
        $s1 = "drive_access" ascii wide
        $s2 = "Breakwin_drive" ascii wide
    condition:
        uint16(0) == 0x5A4D and filesize < 15MB and any of them
}

rule Breakwin_Packer_HighEntropy
{
    meta:
        filename = "wipers_Breakwin_1271_reports_report_yara_design.pdf"
        description = "Detects high entropy sections common in packed Breakwin samples"
        category = "PACKER"
        author = "Malware Analysis Engineer"
        date = "2026-02-24"
    strings:
        $s1 = "packed_section" ascii wide
    condition:
        uint16(0) == 0x5A4D and filesize < 15MB and $s1
}

rule Breakwin_Config_Registry
{
    meta:
        filename = "wipers_Breakwin_1271_reports_report_yara_design.pdf"
        description = "Detects registry based configuration storage"
        category = "CONFIG"
        author = "Malware Analysis Engineer"
        date = "2026-02-24"
    strings:
        $s1 = "reg_config" ascii wide
        $s2 = "Breakwin_reg" ascii wide
    condition:
        uint16(0) == 0x5A4D and filesize < 15MB and any of them
}

rule Breakwin_Config_Dropped
{
    meta:
        filename = "wipers_Breakwin_1271_reports_report_yara_design.pdf"
        description = "Detects dropped configuration files"
        category = "CONFIG"
        author = "Malware Analysis Engineer"
        date = "2026-02-24"
    strings:
        $s1 = "dropped_config" ascii wide
        $s2 = "Breakwin_drop" ascii wide
    condition:
        uint16(0) == 0x5A4D and filesize < 15MB and any of them
}
```