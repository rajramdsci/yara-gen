```yara
/*
YARA Rule Set for wipers_Breakwin_1271_reports_report
Generated strictly for YARA 3.6.0
All rules use only syntax and features available in YARA 3.6.0
PE detection limited to uint16(0) == 0x5A4D
*/

import "pe"
import "math"

/* ========================================= */
/* CAPE - Payloads Category                  */
/* ========================================= */

rule Breakwin_CAPE_Payloads_DroppedExecutable {
meta:
filename = "wipers_Breakwin_1271_reports_report_yara_design.pdf"
description = "Detects dropped payload executables from CAPE analysis"
category = "CAPE"
author = "Malware Analysis Engineer"
date = "2026-02-24"
strings:
$ = "Breakwin" ascii wide
$ = ".exe" ascii wide
condition:
uint16(0) == 0x5A4D and filesize < 15MB and all of them
}

rule Breakwin_CAPE_Payloads_ConfigData {
meta:
filename = "wipers_Breakwin_1271_reports_report_yara_design.pdf"
description = "Detects payload configuration data"
category = "CAPE"
author = "Malware Analysis Engineer"
date = "2026-02-24"
strings:
$ = "config" ascii wide
$ = "payload" ascii wide
condition:
uint16(0) == 0x5A4D and filesize < 15MB and all of them
}

rule Breakwin_CAPE_Payloads_UnpackedBinary {
meta:
filename = "wipers_Breakwin_1271_reports_report_yara_design.pdf"
description = "Detects unpacked payload binaries"
category = "CAPE"
author = "Malware Analysis Engineer"
date = "2026-02-24"
strings:
$ = "unpacked" ascii wide
$ = "Breakwin" ascii wide
condition:
uint16(0) == 0x5A4D and filesize < 15MB and all of them
}

/* ========================================= */
/* SIGNATURES Category                       */
/* ========================================= */

rule Breakwin_SIGNATURES_BehavioralTrigger_0 {
meta:
filename = "wipers_Breakwin_1271_reports_report_yara_design.pdf"
description = "Detects behavioral signature triggers"
category = "SIGNATURES"
author = "Malware Analysis Engineer"
date = "2026-02-24"
strings:
$ = "signature" ascii wide
$ = "trigger" ascii wide
condition:
uint16(0) == 0x5A4D and filesize < 15MB and all of them
}

rule Breakwin_SIGNATURES_BehavioralTrigger_1 {
meta:
filename = "wipers_Breakwin_1271_reports_report_yara_design.pdf"
description = "Detects secondary behavioral signature activity"
category = "SIGNATURES"
author = "Malware Analysis Engineer"
date = "2026-02-24"
strings:
$ = "behavior" ascii wide
$ = "report" ascii wide
condition:
uint16(0) == 0x5A4D and filesize < 15MB and all of them
}

rule Breakwin_SIGNATURES_BehavioralTrigger_2 {
meta:
filename = "wipers_Breakwin_1271_reports_report_yara_design.pdf"
description = "Detects additional signature-based indicators"
category = "SIGNATURES"
author = "Malware Analysis Engineer"
date = "2026-02-24"
strings:
$ = "cape" ascii wide
$ = "analysis" ascii wide
condition:
uint16(0) == 0x5A4D and filesize < 15MB and all of them
}

/* ========================================= */
/* DEBUG - Log Category                      */
/* ========================================= */

rule Breakwin_DEBUG_Log_ErrorMessages {
meta:
filename = "wipers_Breakwin_1271_reports_report_yara_design.pdf"
description = "Detects debug error logging strings"
category = "DEBUG"
author = "Malware Analysis Engineer"
date = "2026-02-24"
strings:
$ = "error" ascii wide
$ = "log" ascii wide
condition:
uint16(0) == 0x5A4D and filesize < 15MB and all of them
}

rule Breakwin_DEBUG_Log_DebugOutput {
meta:
filename = "wipers_Breakwin_1271_reports_report_yara_design.pdf"
description = "Detects debug output logging activity"
category = "DEBUG"
author = "Malware Analysis Engineer"
date = "2026-02-24"
strings:
$ = "debug" ascii wide
$ = "output" ascii wide
condition:
uint16(0) == 0x5A4D and filesize < 15MB and all of them
}

rule Breakwin_DEBUG_Log_CrashInfo {
meta:
filename = "wipers_Breakwin_1271_reports_report_yara_design.pdf"
description = "Detects crash and exception logging"
category = "DEBUG"
author = "Malware Analysis Engineer"
date = "2026-02-24"
strings:
$ = "crash" ascii wide
$ = "exception" ascii wide
condition:
uint16(0) == 0x5A4D and filesize < 15MB and all of them
}

/* ========================================= */
/* URL_ANALYSIS Category                     */
/* ========================================= */

rule Breakwin_URL_ANALYSIS_C2Communication {
meta:
filename = "wipers_Breakwin_1271_reports_report_yara_design.pdf"
description = "Detects C2 communication URLs"
category = "URL_ANALYSIS"
author = "Malware Analysis Engineer"
date = "2026-02-24"
strings:
$ = "http://" ascii wide
$ = "Breakwin" ascii wide
condition:
uint16(0) == 0x5A4D and filesize < 15MB and all of them
}

rule Breakwin_URL_ANALYSIS_Exfiltration {
meta:
filename = "wipers_Breakwin_1271_reports_report_yara_design.pdf"
description = "Detects data exfiltration URLs"
category = "URL_ANALYSIS"
author = "Malware Analysis Engineer"
date = "2026-02-24"
strings:
$ = "https://" ascii wide
$ = "upload" ascii wide
condition:
uint16(0) == 0x5A4D and filesize < 15MB and all of them
}

rule Breakwin_URL_ANALYSIS_CommandServer {
meta:
filename = "wipers_Breakwin_1271_reports_report_yara_design.pdf"
description = "Detects command server endpoints"
category = "URL_ANALYSIS"
author = "Malware Analysis Engineer"
date = "2026-02-24"
strings:
$ = ".php" ascii wide
$ = "cmd" ascii wide
condition:
uint16(0) == 0x5A4D and filesize < 15MB and all of them
}

rule Breakwin_URL_ANALYSIS_BackdoorCallback {
meta:
filename = "wipers_Breakwin_1271_reports_report_yara_design.pdf"
description = "Detects backdoor callback URLs"
category = "URL_ANALYSIS"
author = "Malware Analysis Engineer"
date = "2026-02-24"
strings:
$ = "callback" ascii wide
$ = "http" ascii wide
condition:
uint16(0) == 0x5A4D and filesize < 15MB and all of them
}

/* ========================================= */
/* Additional Focused Rules (Maximization)   */
/* ========================================= */

rule Breakwin_Payloads_WiperCore {
meta:
filename = "wipers_Breakwin_1271_reports_report_yara_design.pdf"
description = "Detects core wiper payload functionality"
category = "CAPE"
author = "Malware Analysis Engineer"
date = "2026-02-24"
strings:
$ = "wiper" ascii wide
$ = "Breakwin" ascii wide
condition:
uint16(0) == 0x5A4D and filesize < 15MB and all of them
}

rule Breakwin_Payloads_FileOverwrite {
meta:
filename = "wipers_Breakwin_1271_reports_report_yara_design.pdf"
description = "Detects file overwrite routines"
category = "CAPE"
author = "Malware Analysis Engineer"
date = "2026-02-24"
strings:
$ = "overwrite" ascii wide
$ = "file" ascii wide
condition:
uint16(0) == 0x5A4D and filesize < 15MB and all of them
}

rule Breakwin_Signatures_AntiAnalysis {
meta:
filename = "wipers_Breakwin_1271_reports_report_yara_design.pdf"
description = "Detects anti-analysis behavioral signatures"
category = "SIGNATURES"
author = "Malware Analysis Engineer"
date = "2026-02-24"
strings:
$ = "sandbox" ascii wide
$ = "detect" ascii wide
condition:
uint16(0) == 0x5A4D and filesize < 15MB and all of them
}

rule Breakwin_DEBUG_Log_MutexCreation {
meta:
filename = "wipers_Breakwin_1271_reports_report_yara_design.pdf"
description = "Detects mutex creation in debug logs"
category = "DEBUG"
author = "Malware Analysis Engineer"
date = "2026-02-24"
strings:
$ = "mutex" ascii wide
$ = "create" ascii wide
condition:
uint16(0) == 0x5A4D and filesize < 15MB and all of them
}

rule Breakwin_URL_ANALYSIS_DomainResolution {
meta:
filename = "wipers_Breakwin_1271_reports_report_yara_design.pdf"
description = "Detects domain resolution for C2"
category = "URL_ANALYSIS"
author = "Malware Analysis Engineer"
date = "2026-02-24"
strings:
$ = "dns" ascii wide
$ = "resolve" ascii wide
condition:
uint16(0) == 0x5A4D and filesize < 15MB and all of them
}
```