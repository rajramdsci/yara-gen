```yara
/*
YARA Rule Set for Rhysida Ransomware
Generated from: ransomeware_Rhysida_684_reports_report_yara_design.pdf
Strictly compliant with YARA 3.6.0 syntax
Maximum number of focused rules created based on provided categories
*/

import "pe"
import "math"

/* ============================================ */
/* CAPE Payloads - Unpacked Payload Detection   */
/* ============================================ */

rule Rhysida_Payload_CAPE_Main
{
    meta:
        filename = "ransomeware_Rhysida_684_reports_report_yara_design.pdf"
        description = "Detects main CAPE payload indicators from Rhysida ransomware"
        category = "CAPE"
        author = "Malware Analysis Engineer"
        date = "2026-02-24"
    strings:
        $s1 = "Rhysida" ascii wide
        $s2 = "Your network has been breached" ascii wide
    condition:
        uint16(0) == 0x5A4D and
        filesize < 15MB and
        any of them
}

rule Rhysida_Payload_CAPE_Encryption
{
    meta:
        filename = "ransomeware_Rhysida_684_reports_report_yara_design.pdf"
        description = "Detects encryption-related payload strings from CAPE report"
        category = "CAPE"
        author = "Malware Analysis Engineer"
        date = "2026-02-24"
    strings:
        $s1 = "encrypt" ascii wide nocase
        $s2 = "AES" ascii wide
    condition:
        uint16(0) == 0x5A4D and
        filesize < 15MB and
        any of them
}

rule Rhysida_Payload_CAPE_RansomNote
{
    meta:
        filename = "ransomeware_Rhysida_684_reports_report_yara_design.pdf"
        description = "Detects ransom note generation in CAPE payloads"
        category = "CAPE"
        author = "Malware Analysis Engineer"
        date = "2026-02-24"
    strings:
        $s1 = "Restore-My-Files" ascii wide
        $s2 = "README" ascii wide
    condition:
        uint16(0) == 0x5A4D and
        filesize < 15MB and
        any of them
}

/* ============================================ */
/* SIGNATURES - Behavioral Signature Rules      */
/* ============================================ */

rule Rhysida_Signatures_Behavior_0
{
    meta:
        filename = "ransomeware_Rhysida_684_reports_report_yara_design.pdf"
        description = "Detects triggered behavioral signatures [0]"
        category = "SIGNATURES"
        author = "Malware Analysis Engineer"
        date = "2026-02-24"
    strings:
        $s1 = "CreateProcess" ascii wide
        $s2 = "VirtualAlloc" ascii wide
    condition:
        uint16(0) == 0x5A4D and
        filesize < 15MB and
        any of them
}

rule Rhysida_Signatures_Process_Injection
{
    meta:
        filename = "ransomeware_Rhysida_684_reports_report_yara_design.pdf"
        description = "Detects process injection signatures"
        category = "SIGNATURES"
        author = "Malware Analysis Engineer"
        date = "2026-02-24"
    strings:
        $s1 = "WriteProcessMemory" ascii wide
        $s2 = "CreateRemoteThread" ascii wide
    condition:
        uint16(0) == 0x5A4D and
        filesize < 15MB and
        any of them
}

rule Rhysida_Signatures_File_Encryption
{
    meta:
        filename = "ransomeware_Rhysida_684_reports_report_yara_design.pdf"
        description = "Detects file encryption behavioral signatures"
        category = "SIGNATURES"
        author = "Malware Analysis Engineer"
        date = "2026-02-24"
    strings:
        $s1 = ".rhysida" ascii wide
        $s2 = "encrypted" ascii wide nocase
    condition:
        uint16(0) == 0x5A4D and
        filesize < 15MB and
        any of them
}

/* ============================================ */
/* DEBUG - Debug and Error Log Detection        */
/* ============================================ */

rule Rhysida_Debug_Log_Error
{
    meta:
        filename = "ransomeware_Rhysida_684_reports_report_yara_design.pdf"
        description = "Detects debug and error logging activity"
        category = "DEBUG"
        author = "Malware Analysis Engineer"
        date = "2026-02-24"
    strings:
        $s1 = "debug" ascii wide nocase
        $s2 = "error" ascii wide nocase
    condition:
        uint16(0) == 0x5A4D and
        filesize < 15MB and
        any of them
}

rule Rhysida_Debug_Log_AntiAnalysis
{
    meta:
        filename = "ransomeware_Rhysida_684_reports_report_yara_design.pdf"
        description = "Detects anti-analysis debug strings"
        category = "DEBUG"
        author = "Malware Analysis Engineer"
        date = "2026-02-24"
    strings:
        $s1 = "sandbox" ascii wide nocase
        $s2 = "vmware" ascii wide nocase
    condition:
        uint16(0) == 0x5A4D and
        filesize < 15MB and
        any of them
}

/* ============================================ */
/* URL_ANALYSIS - Network and C2 Indicators     */
/* ============================================ */

rule Rhysida_URL_Analysis_C2
{
    meta:
        filename = "ransomeware_Rhysida_684_reports_report_yara_design.pdf"
        description = "Detects potential C2 URLs from URL analysis"
        category = "URL_ANALYSIS"
        author = "Malware Analysis Engineer"
        date = "2026-02-24"
    strings:
        $s1 = "http://" ascii wide
        $s2 = "https://" ascii wide
    condition:
        uint16(0) == 0x5A4D and
        filesize < 15MB and
        any of them
}

rule Rhysida_URL_Analysis_Exfil
{
    meta:
        filename = "ransomeware_Rhysida_684_reports_report_yara_design.pdf"
        description = "Detects data exfiltration URL patterns"
        category = "URL_ANALYSIS"
        author = "Malware Analysis Engineer"
        date = "2026-02-24"
    strings:
        $s1 = ".onion" ascii wide
        $s2 = "tor2web" ascii wide
    condition:
        uint16(0) == 0x5A4D and
        filesize < 15MB and
        any of them
}

/* ============================================ */
/* Additional Focused Rhysida Rules             */
/* ============================================ */

rule Rhysida_RansomNote_RestoreMyFiles
{
    meta:
        filename = "ransomeware_Rhysida_684_reports_report_yara_design.pdf"
        description = "Detects specific Rhysida ransom note filename pattern"
        category = "RANSOMNOTE"
        author = "Malware Analysis Engineer"
        date = "2026-02-24"
    strings:
        $s1 = "Restore-My-Files.txt" ascii wide
    condition:
        uint16(0) == 0x5A4D and
        filesize < 15MB and
        $s1
}

rule Rhysida_Packer_HighEntropy
{
    meta:
        filename = "ransomeware_Rhysida_684_reports_report_yara_design.pdf"
        description = "Detects high entropy sections typical of packed Rhysida"
        category = "PACKER"
        author = "Malware Analysis Engineer"
        date = "2026-02-24"
    condition:
        uint16(0) == 0x5A4D and
        filesize < 15MB and
        math.entropy(0, filesize) > 7.0
}

rule Rhysida_Strings_Rhysida
{
    meta:
        filename = "ransomeware_Rhysida_684_reports_report_yara_design.pdf"
        description = "Detects core Rhysida malware identifier string"
        category = "STRINGS"
        author = "Malware Analysis Engineer"
        date = "2026-02-24"
    strings:
        $s1 = "Rhysida" ascii wide
    condition:
        uint16(0) == 0x5A4D and
        filesize < 15MB and
        $s1
}

rule Rhysida_Strings_EncryptionKey
{
    meta:
        filename = "ransomeware_Rhysida_684_reports_report_yara_design.pdf"
        description = "Detects encryption key handling strings"
        category = "STRINGS"
        author = "Malware Analysis Engineer"
        date = "2026-02-24"
    strings:
        $s1 = "publickey" ascii wide nocase
        $s2 = "privatekey" ascii wide nocase
    condition:
        uint16(0) == 0x5A4D and
        filesize < 15MB and
        any of them
}

rule Rhysida_Behavior_DeleteShadowCopies
{
    meta:
        filename = "ransomeware_Rhysida_684_reports_report_yara_design.pdf"
        description = "Detects shadow copy deletion behavior"
        category = "BEHAVIOR"
        author = "Malware Analysis Engineer"
        date = "2026-02-24"
    strings:
        $s1 = "vssadmin" ascii wide nocase
        $s2 = "delete shadows" ascii wide nocase
    condition:
        uint16(0) == 0x5A4D and
        filesize < 15MB and
        any of them
}

rule Rhysida_Behavior_ServiceStop
{
    meta:
        filename = "ransomeware_Rhysida_684_reports_report_yara_design.pdf"
        description = "Detects service stopping behavior"
        category = "BEHAVIOR"
        author = "Malware Analysis Engineer"
        date = "2026-02-24"
    strings:
        $s1 = "sc stop" ascii wide nocase
        $s2 = "net stop" ascii wide nocase
    condition:
        uint16(0) == 0x5A4D and
        filesize < 15MB and
        any of them
}
```