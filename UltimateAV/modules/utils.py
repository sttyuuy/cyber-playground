import os
import hashlib
import math
import magic
import struct
from datetime import datetime

def get_file_type(file_path):
    """Визначає MIME-тип файлу."""
    try:
        return magic.from_file(file_path, mime=True)
    except:
        return 'unknown'

def calculate_entropy(data):
    """Обчислює ентропію Шеннона."""
    if not data:
        return 0
    entropy = 0
    for x in range(256):
        p_x = data.count(x) / len(data)
        if p_x > 0:
            entropy += -p_x * math.log2(p_x)
    return entropy

def get_file_hashes(file_path):
    """Повертає MD5, SHA1, SHA256 хеші файлу."""
    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    sha256 = hashlib.sha256()
    with open(file_path, 'rb') as f:
        for chunk in iter(lambda: f.read(8192), b''):
            md5.update(chunk)
            sha1.update(chunk)
            sha256.update(chunk)
    return md5.hexdigest(), sha1.hexdigest(), sha256.hexdigest()

def is_suspicious_extension(file_path):
    """Перевіряє, чи має файл підозріле розширення."""
    suspicious_ext = ['.exe', '.dll', '.sys', '.vbs', '.js', '.ps1', '.bat', '.cmd', '.scr', '.pif', '.jar', '.apk', '.docm', '.xlsm', '.pptm']
    ext = os.path.splitext(file_path)[1].lower()
    return ext in suspicious_ext

def get_file_size(file_path):
    try:
        return os.path.getsize(file_path)
    except:
        return 0

def safe_read_file(file_path, mode='rb'):
    try:
        with open(file_path, mode) as f:
            return f.read()
    except:
        return None

def timestamp():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")
