```yara
/*
YARA Rule Set for f6f74e05e24dd2e4e60e.exe
Generated from design specification: f6f74e05e24dd2e4e60e_yara_design.pdf
All rules strictly follow YARA 3.6.0 syntax.
*/

import "pe"

/* ============================================ */
/* RANSOMWARE_FILE_MODIFICATIONS */
/* ============================================ */

rule Ransomware_FileMod_Extension_RestoreMyFiles {
meta:
filename = "f6f74e05e24dd2e4e60e_yara_design.pdf"
description = "Detects ransomware file modification indicator RestoreMyFiles"
category = "RANSOMWARE_FILE_MODIFICATIONS"
author = "Malware Analysis Engineer"
date = "2026-02-24"
strings:
$s1 = "Restore-My-Files.txt" ascii wide
$s2 = "Restore-My-Files" ascii wide
condition:
uint16(0) == 0x5A4D and any of them
}

rule Ransomware_FileMod_Extension_LockBit {
meta:
filename = "f6f74e05e24dd2e4e60e_yara_design.pdf"
description = "Detects ransomware file modification indicator LockBit"
category = "RANSOMWARE_FILE_MODIFICATIONS"
author = "Malware Analysis Engineer"
date = "2026-02-24"
strings:
$s1 = ".lockbit" ascii wide
condition:
uint16(0) == 0x5A4D and $s1
}

rule Ransomware_FileMod_ShadowCopy_Deletion {
meta:
filename = "f6f74e05e24dd2e4e60e_yara_design.pdf"
description = "Detects ransomware file modification with shadow copy deletion"
category = "RANSOMWARE_FILE_MODIFICATIONS"
author = "Malware Analysis Engineer"
date = "2026-02-24"
strings:
$s1 = "shadow copies" ascii wide nocase
condition:
uint16(0) == 0x5A4D and $s1
}

/* ============================================ */
/* DELETES_SHADOW_COPIES */
/* ============================================ */

rule DeletesShadowCopies_Vssadmin_Delete {
meta:
filename = "f6f74e05e24dd2e4e60e_yara_design.pdf"
description = "Detects vssadmin shadow copy deletion command"
category = "DELETES_SHADOW_COPIES"
author = "Malware Analysis Engineer"
date = "2026-02-24"
strings:
$s1 = "vssadmin delete shadows" ascii wide nocase
condition:
uint16(0) == 0x5A4D and $s1
}

rule DeletesShadowCopies_Vssadmin_AllQuiet {
meta:
filename = "f6f74e05e24dd2e4e60e_yara_design.pdf"
description = "Detects vssadmin delete shadows /all /quiet"
category = "DELETES_SHADOW_COPIES"
author = "Malware Analysis Engineer"
date = "2026-02-24"
strings:
$s1 = "vssadmin.exe delete shadows /all /quiet" ascii wide nocase
condition:
uint16(0) == 0x5A4D and $s1
}

rule DeletesShadowCopies_Vssadmin_Exec {
meta:
filename = "f6f74e05e24dd2e4e60e_yara_design.pdf"
description = "Detects vssadmin execution for shadow copy deletion"
category = "DELETES_SHADOW_COPIES"
author = "Malware Analysis Engineer"
date = "2026-02-24"
strings:
$s1 = "vssadmin" ascii wide
condition:
uint16(0) == 0x5A4D and $s1
}

/* ============================================ */
/* SUSPICIOUS_COMMAND_TOOLS */
/* ============================================ */

rule SuspiciousCommandTools_Cmd_Exec {
meta:
filename = "f6f74e05e24dd2e4e60e_yara_design.pdf"
description = "Detects heavy use of cmd.exe for destructive actions"
category = "SUSPICIOUS_COMMAND_TOOLS"
author = "Malware Analysis Engineer"
date = "2026-02-24"
strings:
$s1 = "cmd.exe /c" ascii wide
condition:
uint16(0) == 0x5A4D and $s1
}

rule SuspiciousCommandTools_Cmd_Start {
meta:
filename = "f6f74e05e24dd2e4e60e_yara_design.pdf"
description = "Detects cmd.exe start command usage"
category = "SUSPICIOUS_COMMAND_TOOLS"
author = "Malware Analysis Engineer"
date = "2026-02-24"
strings:
$s1 = "cmd.exe /c start" ascii wide
condition:
uint16(0) == 0x5A4D and $s1
}

rule SuspiciousCommandTools_Vssadmin {
meta:
filename = "f6f74e05e24dd2e4e60e_yara_design.pdf"
description = "Detects vssadmin usage in suspicious context"
category = "SUSPICIOUS_COMMAND_TOOLS"
author = "Malware Analysis Engineer"
date = "2026-02-24"
strings:
$s1 = "vssadmin.exe" ascii wide
condition:
uint16(0) == 0x5A4D and $s1
}

rule SuspiciousCommandTools_Wevtutil {
meta:
filename = "f6f74e05e24dd2e4e60e_yara_design.pdf"
description = "Detects wevtutil usage for log manipulation"
category = "SUSPICIOUS_COMMAND_TOOLS"
author = "Malware Analysis Engineer"
date = "2026-02-24"
strings:
$s1 = "wevtutil" ascii wide
condition:
uint16(0) == 0x5A4D and $s1
}

/* ============================================ */
/* CLEARS_LOGS */
/* ============================================ */

rule ClearsLogs_Wevtutil_ClearLog {
meta:
filename = "f6f74e05e24dd2e4e60e_yara_design.pdf"
description = "Detects wevtutil clear-log command"
category = "CLEARS_LOGS"
author = "Malware Analysis Engineer"
date = "2026-02-24"
strings:
$s1 = "wevtutil cl" ascii wide
condition:
uint16(0) == 0x5A4D and $s1
}

rule ClearsLogs_Wevtutil_System {
meta:
filename = "f6f74e05e24dd2e4e60e_yara_design.pdf"
description = "Detects clearing of System event log"
category = "CLEARS_LOGS"
author = "Malware Analysis Engineer"
date = "2026-02-24"
strings:
$s1 = "wevtutil cl System" ascii wide
condition:
uint16(0) == 0x5A4D and $s1
}

rule ClearsLogs_Wevtutil_Security {
meta:
filename = "f6f74e05e24dd2e4e60e_yara_design.pdf"
description = "Detects clearing of Security event log"
category = "CLEARS_LOGS"
author = "Malware Analysis Engineer"
date = "2026-02-24"
strings:
$s1 = "wevtutil cl Security" ascii wide
condition:
uint16(0) == 0x5A4D and $s1
}

rule ClearsLogs_Wevtutil_Application {
meta:
filename = "f6f74e05e24dd2e4e60e_yara_design.pdf"
description = "Detects clearing of Application event log"
category = "CLEARS_LOGS"
author = "Malware Analysis Engineer"
date = "2026-02-24"
strings:
$s1 = "wevtutil cl Application" ascii wide
condition:
uint16(0) == 0x5A4D and $s1
}

rule ClearsLogs_Wevtutil_MassClear {
meta:
filename = "f6f74e05e24dd2e4e60e_yara_design.pdf"
description = "Detects mass wevtutil log clearing activity"
category = "CLEARS_LOGS"
author = "Malware Analysis Engineer"
date = "2026-02-24"
strings:
$s1 = "wevtutil.exe cl" ascii wide
condition:
uint16(0) == 0x5A4D and $s1
}

/* ============================================ */
/* ADDITIONAL BEHAVIORAL INDICATORS */
/* ============================================ */

rule Ransomware_Behavior_ShadowCopy {
meta:
filename = "f6f74e05e24dd2e4e60e_yara_design.pdf"
description = "Detects explicit shadow copy deletion behavior"
category = "DELETES_SHADOW_COPIES"
author = "Malware Analysis Engineer"
date = "2026-02-24"
strings:
$s1 = "delete shadows" ascii wide nocase
condition:
uint16(0) == 0x5A4D and $s1
}

rule Ransomware_Behavior_LogClear {
meta:
filename = "f6f74e05e24dd2e4e60e_yara_design.pdf"
description = "Detects log clearing anti-forensics behavior"
category = "CLEARS_LOGS"
author = "Malware Analysis Engineer"
date = "2026-02-24"
strings:
$s1 = "clear-log" ascii wide
condition:
uint16(0) == 0x5A4D and $s1
}

rule SuspiciousCommandTools_BatchScript {
meta:
filename = "f6f74e05e24dd2e4e60e_yara_design.pdf"
description = "Detects batch script execution for destructive actions"
category = "SUSPICIOUS_COMMAND_TOOLS"
author = "Malware Analysis Engineer"
date = "2026-02-24"
strings:
$s1 = ".bat" ascii wide
$s2 = "cmd.exe" ascii wide
condition:
uint16(0) == 0x5A4D and all of them
}

rule Ransomware_FileMod_RansomNote {
meta:
filename = "f6f74e05e24dd2e4e60e_yara_design.pdf"
description = "Detects potential ransomware note creation"
category = "RANSOMWARE_FILE_MODIFICATIONS"
author = "Malware Analysis Engineer"
date = "2026-02-24"
strings:
$s1 = "README" ascii wide
$s2 = ".txt" ascii wide
condition:
uint16(0) == 0x5A4D and all of them
}
```