import os

# ========== КОНФІГУРАЦІЯ ==========
THRESHOLD_LOW = 30
THRESHOLD_MEDIUM = 50
THRESHOLD_HIGH = 70

# Шляхи
BASE_DIR = os.path.dirname(os.path.dirname(__file__))
REPORTS_DIR = os.path.join(BASE_DIR, 'reports')
QUARANTINE_DIR = os.path.join(BASE_DIR, 'quarantine')
SIGNATURES_DIR = os.path.join(BASE_DIR, 'signatures')

# Налаштування сканування
SCAN_ARCHIVES = True
SCAN_OFFICE = True
SCAN_PDF = True
SCAN_SCRIPTS = True
SCAN_PE = True
SCAN_ELF = True
SCAN_MACHO = True

# Поведінковий аналіз
ENABLE_BEHAVIORAL = True
BEHAVIORAL_SAMPLE_TIME = 5  # секунд

# Хмарна перевірка (VirusTotal)
VT_API_KEY = ""  # встав свій ключ
VT_API_URL = "https://www.virustotal.com/api/v3/files/"

# Евристика
ENTROPY_THRESHOLD = 7.2
SUSPICIOUS_API_LIST = [
    "CreateRemoteThread", "WriteProcessMemory", "VirtualAllocEx",
    "GetProcAddress", "LoadLibrary", "WinExec", "ShellExecute",
    "RegSetValue", "RegDeleteKey", "DeleteFile", "MoveFile",
    "Socket", "Connect", "Send", "Recv", "InternetOpen",
    "URLDownloadToFile", "WinHttpOpen", "HttpSendRequest",
    "CryptEncrypt", "CryptDecrypt", "BlockInput",
    "SetWindowsHookEx", "GetAsyncKeyState", "GetKeyState",
    "NtQueryInformationProcess", "IsDebuggerPresent",
    "OutputDebugString", "CloseHandle", "OpenProcess",
    "CreateProcess", "TerminateProcess", "EnumProcesses"
]
