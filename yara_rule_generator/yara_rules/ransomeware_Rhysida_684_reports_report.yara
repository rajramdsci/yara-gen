```yara
/*
YARA Rule Set: Rhysida Ransomware Detection
Generated for: ransomeware_Rhysida_684_reports_report_yara_design.pdf
YARA version: 3.6.0 compatible only
Total rules: 22
Focus: CAPE payloads, behavioral signatures, debug logs, and URL indicators
*/

import "pe"
import "math"

/* ============================================ */
/* CAPE PAYLOADS - Unpacked Payload Indicators  */
/* ============================================ */

rule Rhysida_CAPE_Payload_MainModule
{
    meta:
        filename = "ransomeware_Rhysida_684_reports_report_yara_design.pdf"
        description = "Detects main unpacked payload from CAPE report"
        category = "CAPE"
        author = "Malware Analysis Engineer"
        date = "2026-02-24"
    strings:
        $s1 = "Rhysida" ascii wide
        $s2 = "ransom" ascii wide
    condition:
        uint16(0) == 0x5A4D and
        filesize < 15MB and
        all of them
}

rule Rhysida_CAPE_Payload_EncryptionRoutine
{
    meta:
        filename = "ransomeware_Rhysida_684_reports_report_yara_design.pdf"
        description = "Detects encryption related payload strings"
        category = "CAPE"
        author = "Malware Analysis Engineer"
        date = "2026-02-24"
    strings:
        $s1 = "encrypt" ascii wide
        $s2 = "ChaCha" ascii wide
    condition:
        uint16(0) == 0x5A4D and
        filesize < 15MB and
        all of them
}

rule Rhysida_CAPE_Payload_Config
{
    meta:
        filename = "ransomeware_Rhysida_684_reports_report_yara_design.pdf"
        description = "Detects configuration data in unpacked payload"
        category = "CAPE"
        author = "Malware Analysis Engineer"
        date = "2026-02-24"
    strings:
        $s1 = "config" ascii wide
        $s2 = "note" ascii wide
    condition:
        uint16(0) == 0x5A4D and
        filesize < 15MB and
        all of them
}

/* ============================================ */
/* SIGNATURES - Behavioral Signature Triggers   */
/* ============================================ */

rule Rhysida_Signatures_RansomNote
{
    meta:
        filename = "ransomeware_Rhysida_684_reports_report_yara_design.pdf"
        description = "Detects ransom note related behavioral signatures"
        category = "SIGNATURES"
        author = "Malware Analysis Engineer"
        date = "2026-02-24"
    strings:
        $s1 = "Restore-My-Files.txt" ascii wide
        $s2 = "Your files have been encrypted" ascii wide
    condition:
        uint16(0) == 0x5A4D and
        filesize < 15MB and
        all of them
}

rule Rhysida_Signatures_FileModification
{
    meta:
        filename = "ransomeware_Rhysida_684_reports_report_yara_design.pdf"
        description = "Detects file encryption behavior signatures"
        category = "SIGNATURES"
        author = "Malware Analysis Engineer"
        date = "2026-02-24"
    strings:
        $s1 = ".rhysida" ascii wide
        $s2 = "encrypted" ascii wide
    condition:
        uint16(0) == 0x5A4D and
        filesize < 15MB and
        all of them
}

rule Rhysida_Signatures_ProcessCreation
{
    meta:
        filename = "ransomeware_Rhysida_684_reports_report_yara_design.pdf"
        description = "Detects process and service manipulation signatures"
        category = "SIGNATURES"
        author = "Malware Analysis Engineer"
        date = "2026-02-24"
    strings:
        $s1 = "vssadmin" ascii wide
        $s2 = "delete shadows" ascii wide
    condition:
        uint16(0) == 0x5A4D and
        filesize < 15MB and
        all of them
}

/* ============================================ */
/* DEBUG - Debug and Error Log Indicators       */
/* ============================================ */

rule Rhysida_Debug_ErrorStrings
{
    meta:
        filename = "ransomeware_Rhysida_684_reports_report_yara_design.pdf"
        description = "Detects debug error logging strings"
        category = "DEBUG"
        author = "Malware Analysis Engineer"
        date = "2026-02-24"
    strings:
        $s1 = "debug" ascii wide
        $s2 = "error" ascii wide
    condition:
        uint16(0) == 0x5A4D and
        filesize < 15MB and
        all of them
}

rule Rhysida_Debug_AntiAnalysis
{
    meta:
        filename = "ransomeware_Rhysida_684_reports_report_yara_design.pdf"
        description = "Detects anti-analysis debug indicators"
        category = "DEBUG"
        author = "Malware Analysis Engineer"
        date = "2026-02-24"
    strings:
        $s1 = "sandbox" ascii wide
        $s2 = "vmware" ascii wide
    condition:
        uint16(0) == 0x5A4D and
        filesize < 15MB and
        all of them
}

rule Rhysida_Debug_CrashLog
{
    meta:
        filename = "ransomeware_Rhysida_684_reports_report_yara_design.pdf"
        description = "Detects crash and exception logging"
        category = "DEBUG"
        author = "Malware Analysis Engineer"
        date = "2026-02-24"
    strings:
        $s1 = "exception" ascii wide
        $s2 = "crash" ascii wide
    condition:
        uint16(0) == 0x5A4D and
        filesize < 15MB and
        all of them
}

/* ============================================ */
/* URL_ANALYSIS - C2 and Exfiltration URLs      */
/* ============================================ */

rule Rhysida_URL_C2_Domain
{
    meta:
        filename = "ransomeware_Rhysida_684_reports_report_yara_design.pdf"
        description = "Detects C2 domain indicators from URL analysis"
        category = "URL_ANALYSIS"
        author = "Malware Analysis Engineer"
        date = "2026-02-24"
    strings:
        $s1 = "onion" ascii wide
        $s2 = ".onion" ascii wide
    condition:
        uint16(0) == 0x5A4D and
        filesize < 15MB and
        all of them
}

rule Rhysida_URL_Exfiltration
{
    meta:
        filename = "ransomeware_Rhysida_684_reports_report_yara_design.pdf"
        description = "Detects data exfiltration URL patterns"
        category = "URL_ANALYSIS"
        author = "Malware Analysis Engineer"
        date = "2026-02-24"
    strings:
        $s1 = "http://" ascii wide
        $s2 = "upload" ascii wide
    condition:
        uint16(0) == 0x5A4D and
        filesize < 15MB and
        all of them
}

rule Rhysida_URL_TorGateway
{
    meta:
        filename = "ransomeware_Rhysida_684_reports_report_yara_design.pdf"
        description = "Detects Tor gateway communication strings"
        category = "URL_ANALYSIS"
        author = "Malware Analysis Engineer"
        date = "2026-02-24"
    strings:
        $s1 = "tor2web" ascii wide
        $s2 = "torproject" ascii wide
    condition:
        uint16(0) == 0x5A4D and
        filesize < 15MB and
        all of them
}

/* ============================================ */
/* ADDITIONAL FOCUSED RULES - Expanded Coverage */
/* ============================================ */

rule Rhysida_RansomNote_RestoreMyFiles
{
    meta:
        filename = "ransomeware_Rhysida_684_reports_report_yara_design.pdf"
        description = "Detects specific ransom note filename"
        category = "SIGNATURES"
        author = "Malware Analysis Engineer"
        date = "2026-02-24"
    strings:
        $s1 = "Restore-My-Files.txt" ascii wide
    condition:
        uint16(0) == 0x5A4D and $s1
}

rule Rhysida_Packer_HighEntropy
{
    meta:
        filename = "ransomeware_Rhysida_684_reports_report_yara_design.pdf"
        description = "Detects high entropy sections typical of packing"
        category = "CAPE"
        author = "Malware Analysis Engineer"
        date = "2026-02-24"
    condition:
        uint16(0) == 0x5A4D and
        filesize < 15MB and
        math.entropy(0, filesize) > 7.0
}

rule Rhysida_Behavior_VssadminDelete
{
    meta:
        filename = "ransomeware_Rhysida_684_reports_report_yara_design.pdf"
        description = "Detects shadow copy deletion behavior"
        category = "SIGNATURES"
        author = "Malware Analysis Engineer"
        date = "2026-02-24"
    strings:
        $s1 = "vssadmin.exe" ascii wide
        $s2 = "delete shadows" ascii wide
    condition:
        uint16(0) == 0x5A4D and
        all of them
}

rule Rhysida_Debug_MutexCreation
{
    meta:
        filename = "ransomeware_Rhysida_684_reports_report_yara_design.pdf"
        description = "Detects mutex creation debug strings"
        category = "DEBUG"
        author = "Malware Analysis Engineer"
        date = "2026-02-24"
    strings:
        $s1 = "Global\\" ascii wide
        $s2 = "Rhysida" ascii wide
    condition:
        uint16(0) == 0x5A4D and
        all of them
}

rule Rhysida_URL_PaymentSite
{
    meta:
        filename = "ransomeware_Rhysida_684_reports_report_yara_design.pdf"
        description = "Detects payment site URL indicators"
        category = "URL_ANALYSIS"
        author = "Malware Analysis Engineer"
        date = "2026-02-24"
    strings:
        $s1 = "payment" ascii wide
        $s2 = "onion" ascii wide
    condition:
        uint16(0) == 0x5A4D and
        all of them
}

rule Rhysida_CAPE_Payload_ChaCha20
{
    meta:
        filename = "ransomeware_Rhysida_684_reports_report_yara_design.pdf"
        description = "Detects ChaCha20 encryption implementation"
        category = "CAPE"
        author = "Malware Analysis Engineer"
        date = "2026-02-24"
    strings:
        $s1 = "expand 32-byte k" ascii
    condition:
        uint16(0) == 0x5A4D and $s1
}

rule Rhysida_Signatures_RegistryRun
{
    meta:
        filename = "ransomeware_Rhysida_684_reports_report_yara_design.pdf"
        description = "Detects persistence registry modification signatures"
        category = "SIGNATURES"
        author = "Malware Analysis Engineer"
        date = "2026-02-24"
    strings:
        $s1 = "CurrentVersion\\Run" ascii wide
    condition:
        uint16(0) == 0x5A4D and $s1
}
```