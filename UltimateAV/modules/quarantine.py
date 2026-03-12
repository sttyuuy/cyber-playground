import os
import shutil
from datetime import datetime
from . import config

def move_to_quarantine(file_path):
    if not os.path.isfile(file_path):
        return False
    try:
        base = os.path.basename(file_path)
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        dest = os.path.join(config.QUARANTINE_DIR, f"{ts}_{base}")
        shutil.move(file_path, dest)
        return True
    except:
        return False

def restore_from_quarantine(file_name, restore_path):
    src = os.path.join(config.QUARANTINE_DIR, file_name)
    if os.path.isfile(src):
        shutil.move(src, restore_path)
        return True
    return False

def delete_from_quarantine(file_name):
    file_path = os.path.join(config.QUARANTINE_DIR, file_name)
    try:
        os.remove(file_path)
        return True
    except:
        return False

def list_quarantine():
    return os.listdir(config.QUARANTINE_DIR) if os.path.exists(config.QUARANTINE_DIR) else []
