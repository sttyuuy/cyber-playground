import requests
import hashlib
from . import config

class CloudScanner:
    def __init__(self):
        self.api_key = config.VT_API_KEY
        self.cache = {}

    def check_hash(self, file_hash):
        """Перевіряє хеш через VirusTotal API."""
        if not self.api_key:
            return None
        if file_hash in self.cache:
            return self.cache[file_hash]
        url = config.VT_API_URL + file_hash
        headers = {'x-apikey': self.api_key}
        try:
            response = requests.get(url, headers=headers, timeout=5)
            if response.status_code == 200:
                data = response.json()
                stats = data['data']['attributes']['last_analysis_stats']
                malicious = stats.get('malicious', 0)
                suspicious = stats.get('suspicious', 0)
                self.cache[file_hash] = (malicious + suspicious) > 0
                return self.cache[file_hash]
        except:
            pass
        return None

    def report_malware(self, file_path, analysis):
        """Відправляє зразок на аналіз (заглушка)."""
        # У реальному проекті тут можна реалізувати завантаження файлу на свій сервер
        pass
