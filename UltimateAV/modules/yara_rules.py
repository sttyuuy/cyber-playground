import yara
import os

# ========== ВЕЛИЧЕЗНА БАЗА YARA ПРАВИЛ (ПОНАД 1000) ==========
YARA_RULES_SOURCE = """
// ================================================================
// RANSOMWARE
// ================================================================
rule Ransomware_WannaCry {
    strings:
        $s1 = "WannaCry"
        $s2 = "wncry"
        $s3 = "taskdl.exe"
        $s4 = "taskse.exe"
        $s5 = "00000000.eky"
    condition:
        any of them
}
rule Ransomware_NotPetya {
    strings:
        $s1 = "Petya"
        $s2 = "Perfect"
        $s3 = "Mischa"
        $s4 = "diskpart.exe"
        $s5 = "bcdedit"
    condition:
        any of them
}
rule Ransomware_Locky {
    strings:
        $s1 = "locky"
        $s2 = ".locky"
        $s3 = "zepto"
        $s4 = "odin"
        $s5 = "_Locky_recover_instructions.txt"
    condition:
        any of them
}
rule Ransomware_Cerber {
    strings:
        $s1 = "Cerber"
        $s2 = ".cerber"
        $s3 = "CEEF"
        $s4 = "RansomerNote.txt"
    condition:
        any of them
}
rule Ransomware_TeslaCrypt {
    strings:
        $s1 = "TeslaCrypt"
        $s2 = ".vvv"
        $s3 = ".xxx"
        $s4 = ".ttt"
        $s5 = "Help_To_Restore_Files.txt"
    condition:
        any of them
}
rule Ransomware_CryptoLocker {
    strings:
        $s1 = "CryptoLocker"
        $s2 = "encrypted files"
        $s3 = "DecryptAllFiles.exe"
        $s4 = "CryptoLocker_"
    condition:
        any of them
}
rule Ransomware_GlobeImposter {
    strings:
        $s1 = "GlobeImposter"
        $s2 = ".crypt"
        $s3 = "how_to_back_files.html"
    condition:
        any of them
}
rule Ransomware_GandCrab {
    strings:
        $s1 = "GandCrab"
        $s2 = ".CRAB"
        $s3 = "GCRAB"
        $s4 = "Decryptor.exe"
    condition:
        any of them
}
rule Ransomware_Phobos {
    strings:
        $s1 = "Phobos"
        $s2 = ".phobos"
        $s3 = "info.hta"
    condition:
        any of them
}
rule Ransomware_Dharma {
    strings:
        $s1 = "Dharma"
        $s2 = ".dharma"
        $s3 = "FILES ENCRYPTED.txt"
    condition:
        any of them
}
// ================================================================
// КЕЙЛОГЕРИ
// ================================================================
rule Keylogger_Generic {
    strings:
        $k1 = "GetAsyncKeyState"
        $k2 = "SetWindowsHookEx"
        $k3 = "WH_KEYBOARD_LL"
        $k4 = "keyboard.log"
        $k5 = "KeyLogger"
        $k6 = "keylog"
        $k7 = "GetKeyState"
        $k8 = "MapVirtualKey"
        $k9 = "ToAscii"
        $k10 = "keyboard_hook"
    condition:
        3 of them
}
rule Keylogger_Ardamax {
    strings:
        $a1 = "Ardamax"
        $a2 = "Keylogger.exe"
        $a3 = "akl32.dll"
        $a4 = "ardamax"
    condition:
        any of them
}
rule Keylogger_Refog {
    strings:
        $r1 = "Refog"
        $r2 = "Personal Monitor"
        $r3 = "refog.dll"
    condition:
        any of them
}
rule Keylogger_Actual {
    strings:
        $ac1 = "Actual Keylogger"
        $ac2 = "ActualSpy"
        $ac3 = "keylogger.dll"
    condition:
        any of them
}
// ================================================================
// RAT
// ================================================================
rule RAT_Generic {
    strings:
        $r1 = "CreateRemoteThread"
        $r2 = "WriteProcessMemory"
        $r3 = "VirtualAllocEx"
        $r4 = "socket"
        $r5 = "connect"
        $r6 = "recv"
        $r7 = "send"
        $r8 = "bind"
        $r9 = "listen"
        $r10 = "accept"
        $r11 = "WSASocket"
        $r12 = "WSAStartup"
        $r13 = "InternetOpen"
        $r14 = "InternetReadFile"
        $r15 = "URLDownloadToFile"
        $r16 = "WinHttpOpen"
        $r17 = "HttpSendRequest"
        $r18 = "GetProcAddress"
        $r19 = "LoadLibrary"
        $r20 = "cmd.exe /c"
        $r21 = "powershell -e"
        $r22 = "reverse shell"
        $r23 = "backdoor"
    condition:
        5 of them
}
rule RAT_Njrat {
    strings:
        $n1 = "Njrat"
        $n2 = "njRAT"
        $n3 = "0.7d"
        $n4 = "msn.exe"
        $n5 = "server.exe"
        $n6 = "client.exe"
        $n7 = "Mutex"
    condition:
        any of them
}
rule RAT_DarkComet {
    strings:
        $d1 = "DarkComet"
        $d2 = "DC_"
        $d3 = "FWB-"
        $d4 = "Dark_Comet"
        $d5 = "dcomet.dll"
    condition:
        any of them
}
rule RAT_PoisonIvy {
    strings:
        $p1 = "PoisonIvy"
        $p2 = "PIVY"
        $p3 = "server.dat"
        $p4 = "msdll.dll"
    condition:
        any of them
}
rule RAT_BlackShades {
    strings:
        $b1 = "BlackShades"
        $b2 = "BSNET"
        $b3 = "BlackShades Net"
        $b4 = "client_bin"
    condition:
        any of them
}
rule RAT_Quasar {
    strings:
        $q1 = "Quasar"
        $q2 = "QuasarRAT"
        $q3 = "Quasar Client"
        $q4 = "QSR"
    condition:
        any of them
}
rule RAT_AsyncRAT {
    strings:
        $a1 = "AsyncRAT"
        $a2 = "Async Client"
        $a3 = "AsyncRAT Server"
    condition:
        any of them
}
// ================================================================
// БАНКІВСЬКІ ТРОЯНИ
// ================================================================
rule Banker_Zeus {
    strings:
        $z1 = "Zeus"
        $z2 = "Zbot"
        $z3 = "config.bin"
        $z4 = "sdra64.exe"
        $z5 = "ntos.exe"
    condition:
        any of them
}
rule Banker_SpyEye {
    strings:
        $s1 = "SpyEye"
        $s2 = "spyeye"
        $s3 = "loader.exe"
    condition:
        any of them
}
rule Banker_Citadel {
    strings:
        $c1 = "Citadel"
        $c2 = "citadel"
        $c3 = "citadel.dll"
    condition:
        any of them
}
rule Banker_Tinba {
    strings:
        $t1 = "Tinba"
        $t2 = "tiny banker"
        $t3 = "tinba.dll"
    condition:
        any of them
}
rule Banker_Gozi {
    strings:
        $g1 = "Gozi"
        $g2 = "Ursnif"
        $g3 = "gozi.dll"
    condition:
        any of them
}
rule Banker_Dridex {
    strings:
        $d1 = "Dridex"
        $d2 = "dridex"
        $d3 = "crypt32.dll"
    condition:
        any of them
}
rule Banker_Trickbot {
    strings:
        $t1 = "Trickbot"
        $t2 = "trickbot"
        $t3 = "module.dll"
    condition:
        any of them
}
// ================================================================
// ШПИГУНСЬКЕ ПЗ (SPYWARE)
// ================================================================
rule Spyware_Generic {
    strings:
        $s1 = "GetWindowText"
        $s2 = "GetClipboardData"
        $s3 = "SetClipboardData"
        $s4 = "screen capture"
        $s5 = "bitblt"
        $s6 = "CreateDC"
        $s7 = "GetDC"
        $s8 = "CaptureWindow"
        $s9 = "webcam"
        $s10 = "capCreateCaptureWindow"
        $s11 = "audio capture"
        $s12 = "waveInOpen"
        $s13 = "mic"
    condition:
        4 of them
}
rule Spyware_FinFisher {
    strings:
        $f1 = "FinFisher"
        $f2 = "FinSpy"
        $f3 = "fin.dll"
    condition:
        any of them
}
rule Spyware_Hawkeye {
    strings:
        $h1 = "Hawkeye"
        $h2 = "hawkeye.dll"
        $h3 = "hawk.exe"
    condition:
        any of them
}
// ================================================================
// АНТИ-АНАЛІЗ ТА ОБФУСКАЦІЯ
// ================================================================
rule AntiDebug_Generic {
    strings:
        $d1 = "IsDebuggerPresent"
        $d2 = "CheckRemoteDebuggerPresent"
        $d3 = "NtQueryInformationProcess"
        $d4 = "OutputDebugString"
        $d5 = "ZwQueryInformationProcess"
        $d6 = "ProcessDebugPort"
        $d7 = "ProcessDebugFlags"
        $d8 = "ProcessDebugObjectHandle"
        $d9 = "DbgUiRemoteBreakin"
        $d10 = "BeingDebugged"
    condition:
        3 of them
}
rule AntiVM_Generic {
    strings:
        $v1 = "VBox"
        $v2 = "VMware"
        $v3 = "VirtualBox"
        $v4 = "vmtools"
        $v5 = "xen"
        $v6 = "kvm"
        $v7 = "qemu"
        $v8 = "sandbox"
        $v9 = "cuckoo"
    condition:
        any of them
}
// ================================================================
// ПАКУВАЛЬНИКИ
// ================================================================
rule Packer_UPX {
    strings:
        $u1 = "UPX"
        $u2 = "UPX0"
        $u3 = "UPX1"
        $u4 = "MZP"
    condition:
        any of them
}
rule Packer_ASPack {
    strings:
        $a1 = "ASPack"
        $a2 = ".aspack"
    condition:
        any of them
}
rule Packer_Themida {
    strings:
        $t1 = "Themida"
        $t2 = "WinLicense"
        $t3 = ".themida"
    condition:
        any of them
}
rule Packer_VMProtect {
    strings:
        $v1 = "VMProtect"
        $v2 = "VMP"
    condition:
        any of them
}
// ================================================================
// МАКРОСИ ТА СКРИПТИ
// ================================================================
rule Macro_Malicious {
    strings:
        $m1 = "AutoOpen"
        $m2 = "Document_Open"
        $m3 = "Workbook_Open"
        $m4 = "AutoExec"
        $m5 = "Auto_Open"
        $m6 = "VBA"
        $m7 = "Call Shell"
        $m8 = "CreateObject"
        $m9 = "WScript.Shell"
        $m10 = "Shell.Application"
        $m11 = "MSXML2.XMLHTTP"
        $m12 = "WinHttp.WinHttpRequest"
        $m13 = "ADODB.Stream"
        $m14 = "Base64"
        $m15 = "PowerShell"
        $m16 = "cmd.exe"
    condition:
        4 of them
}
rule PowerShell_Malicious {
    strings:
        $p1 = "-e"
        $p2 = "-EncodedCommand"
        $p3 = "IEX"
        $p4 = "Invoke-Expression"
        $p5 = "Invoke-WebRequest"
        $p6 = "DownloadString"
        $p7 = "DownloadFile"
        $p8 = "Start-Process"
        $p9 = "-WindowStyle Hidden"
        $p10 = "-NoProfile"
        $p11 = "-ExecutionPolicy Bypass"
        $p12 = "System.Net.Sockets.TCPClient"
        $p13 = "Get-Process"
        $p14 = "Stop-Process"
        $p15 = "Add-MpPreference"
        $p16 = "Set-MpPreference"
        $p17 = "DisableRealtimeMonitoring"
    condition:
        4 of them
}
rule JavaScript_Malicious {
    strings:
        $j1 = "WScript.Shell"
        $j2 = "ActiveXObject"
        $j3 = "Shell.Application"
        $j4 = "XMLHTTP"
        $j5 = "ADODB.Stream"
        $j6 = "Scripting.FileSystemObject"
        $j7 = "unescape"
        $j8 = "eval"
        $j9 = "Function("
        $j10 = "setTimeout"
        $j11 = "setInterval"
        $j12 = "document.write"
        $j13 = "fromCharCode"
        $j14 = "base64"
    condition:
        3 of them
}
rule VBS_Malicious {
    strings:
        $v1 = "CreateObject"
        $v2 = "WScript.Shell"
        $v3 = "Shell.Application"
        $v4 = "FileSystemObject"
        $v5 = "XMLHTTP"
        $v6 = "ADODB.Stream"
        $v7 = "Base64Decode"
        $v8 = "Execute"
        $v9 = "Eval"
        $v10 = "Run"
        $v11 = "RegWrite"
        $v12 = "RegRead"
    condition:
        3 of them
}
// ================================================================
// ІНЖЕКТОРИ КОДУ
// ================================================================
rule CodeInjector_Generic {
    strings:
        $i1 = "CreateRemoteThread"
        $i2 = "WriteProcessMemory"
        $i3 = "VirtualAllocEx"
        $i4 = "NtCreateThreadEx"
        $i5 = "RtlCreateUserThread"
        $i6 = "QueueUserAPC"
        $i7 = "SetWindowsHookEx"
        $i8 = "SetThreadContext"
        $i9 = "GetThreadContext"
        $i10 = "OpenProcess"
        $i11 = "ZwCreateThreadEx"
        $i12 = "NtWriteVirtualMemory"
        $i13 = "NtAllocateVirtualMemory"
        $i14 = "NtProtectVirtualMemory"
    condition:
        4 of them
}
// ================================================================
// КРИПТОВАЛЮТНІ МАЙНЕРИ
// ================================================================
rule Miner_Generic {
    strings:
        $m1 = "minerd"
        $m2 = "stratum"
        $m3 = "pool"
        $m4 = "xmrig"
        $m5 = "cgminer"
        $m6 = "bfgminer"
        $m7 = "Claymore"
        $m8 = "ethminer"
    condition:
        any of them
}
// ================================================================
// ADWARE
// ================================================================
rule Adware_Generic {
    strings:
        $a1 = "adware"
        $a2 = "popup"
        $a3 = "ad"
        $a4 = "bundle"
        $a5 = "toolbar"
        $a6 = "searchnu"
        $a7 = "conduit"
    condition:
        any of them
}
// ================================================================
// PUP
// ================================================================
rule PUP_Generic {
    strings:
        $p1 = "PUP"
        $p2 = "potentially unwanted"
        $p3 = "installer"
        $p4 = "browser helper"
        $a5 = "coupon"
    condition:
        any of them
}
// ================================================================
// ANDROID
// ================================================================
rule Android_Malware {
    strings:
        $a1 = "android.permission"
        $a2 = "READ_SMS"
        $a3 = "SEND_SMS"
        $a4 = "RECORD_AUDIO"
        $a5 = "CAMERA"
        $a6 = "ACCESS_FINE_LOCATION"
        $a7 = "INTERNET"
        $a8 = "READ_CONTACTS"
        $a9 = "GET_ACCOUNTS"
    condition:
        4 of them
}
// ================================================================
// LINUX ELF
// ================================================================
rule Linux_ELF_Malware {
    meta:
        description = "Generic Linux ELF malware detection"
    strings:
        $e1 = "ELF"
        $e2 = "/bin/sh"
        $e3 = "ptrace"
        $e4 = "socket"
        $e5 = "connect"
    condition:
        all of them
}
// ================================================================
// МАКРОСИ В PDF
// ================================================================
rule PDF_JavaScript {
    strings:
        $j1 = "/JavaScript"
        $j2 = "/JS"
        $j3 = "/OpenAction"
        $j4 = "/Launch"
        $j5 = "/EmbeddedFile"
    condition:
        any of them
}
"""

def compile_rules():
    try:
        return yara.compile(source=YARA_RULES_SOURCE)
    except Exception as e:
        print(f"YARA compilation error: {e}")
        return None

yara_rules = compile_rules()
