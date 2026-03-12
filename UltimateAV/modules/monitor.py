import psutil
import time
import threading
from datetime import datetime
from . import config

class ProcessMonitor:
    def __init__(self):
        self.suspicious_behaviors = []
        self.process_history = {}
        self.monitoring = False
        self.thread = None

    def start(self):
        if config.ENABLE_BEHAVIORAL:
            self.monitoring = True
            self.thread = threading.Thread(target=self._monitor_loop)
            self.thread.daemon = True
            self.thread.start()

    def stop(self):
        self.monitoring = False

    def _monitor_loop(self):
        while self.monitoring:
            self._check_new_processes()
            self._check_network_connections()
            time.sleep(2)

    def _check_new_processes(self):
        for proc in psutil.process_iter(['pid', 'name', 'exe', 'cmdline', 'connections']):
            try:
                pid = proc.info['pid']
                if pid not in self.process_history:
                    self.process_history[pid] = {
                        'start_time': datetime.now(),
                        'name': proc.info['name'],
                        'exe': proc.info['exe'],
                        'cmdline': proc.info['cmdline']
                    }
                    self._analyze_process(proc)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass

    def _analyze_process(self, proc):
        try:
            # Підозрілі імена процесів
            suspicious_names = ['rundll32.exe', 'regsvr32.exe', 'svchost.exe', 'powershell.exe', 'cmd.exe']
            if proc.info['name'].lower() in suspicious_names:
                # Перевіряємо, чи їхні командні рядки містять підозрілі аргументи
                cmdline = ' '.join(proc.info['cmdline']).lower() if proc.info['cmdline'] else ''
                if ' -e ' in cmdline or 'encodedcommand' in cmdline or 'downloadstring' in cmdline:
                    self.suspicious_behaviors.append({
                        'time': datetime.now(),
                        'process': proc.info['name'],
                        'pid': proc.info['pid'],
                        'type': 'suspicious_commandline',
                        'cmdline': cmdline[:200]
                    })

            # Перевірка на ін'єкцію коду (наявність дескрипторів інших процесів)
            try:
                if proc.info['name'].lower() == 'rundll32.exe':
                    # Перевіряємо, чи відкриває він чужі процеси
                    for conn in proc.connections():
                        if conn.type == psutil.CONN_TCP and conn.status == 'LISTEN':
                            self.suspicious_behaviors.append({
                                'time': datetime.now(),
                                'process': proc.info['name'],
                                'pid': proc.info['pid'],
                                'type': 'listening_port',
                                'port': conn.laddr.port
                            })
            except:
                pass
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass

    def _check_network_connections(self):
        for conn in psutil.net_connections():
            if conn.status == 'ESTABLISHED' and conn.raddr:
                if conn.raddr.port in [4444, 1337, 31337, 6667, 5555, 8080]:
                    try:
                        proc = psutil.Process(conn.pid)
                        self.suspicious_behaviors.append({
                            'time': datetime.now(),
                            'process': proc.name(),
                            'pid': conn.pid,
                            'type': 'suspicious_connection',
                            'remote': f"{conn.raddr.ip}:{conn.raddr.port}"
                        })
                    except:
                        pass

    def get_behaviors(self):
        return self.suspicious_behaviors
