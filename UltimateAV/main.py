import tkinter as tk
from tkinter import ttk, filedialog, scrolledtext, messagebox
import threading
import os
import sys
from datetime import datetime

sys.path.append(os.path.dirname(__file__))
from modules import scanner, monitor, cloud, sandbox, quarantine, report, config

class UltimateAVApp:
    def __init__(self, root):
        self.root = root
        self.root.title("🔥 НЕЙМОВІРНИЙ АНТИВІРУС v7.0")
        self.root.geometry("1300x850")
        self.root.configure(bg='#0a0a0a')

        self.monitor = monitor.ProcessMonitor()
        self.monitor.start()

        self.cloud = cloud.CloudScanner()

        self.sandbox = sandbox.Sandbox()

        self.create_widgets()

        self.log("🔥 АНТИВІРУС АКТИВОВАНО", 'critical')
        self.log("⚡ Глибокий аналіз усіх типів файлів | Понад 1000 YARA правил | Поведінковий моніторинг", 'info')
        self.log("☁️ Інтеграція з VirusTotal | Емуляція пісочниці | Карантин | Детальні звіти", 'info')

    def create_widgets(self):
        title = tk.Label(self.root, text="🛡️ НАЙПОТУЖНІШИЙ АНТИВІРУС", font=('Consolas', 22, 'bold'),
                         bg='#0a0a0a', fg='#00ff00')
        title.pack(pady=10)

        btn_frame = tk.Frame(self.root, bg='#0a0a0a')
        btn_frame.pack(pady=10)

        self.btn_file = tk.Button(btn_frame, text="🔍 Аналіз файлу", command=self.analyze_file,
                                  bg='#1e1e1e', fg='#00ff00', width=20, height=2, font=('Consolas', 11))
        self.btn_file.pack(side=tk.LEFT, padx=5)

        self.btn_dir = tk.Button(btn_frame, text="📁 Аналіз теки", command=self.analyze_dir,
                                 bg='#1e1e1e', fg='#00ff00', width=20, height=2, font=('Consolas', 11))
        self.btn_dir.pack(side=tk.LEFT, padx=5)

        self.btn_monitor = tk.Button(btn_frame, text="👁️ Показати поведінку", command=self.show_behaviors,
                                     bg='#1e1e1e', fg='#00ff00', width=20, height=2, font=('Consolas', 11))
        self.btn_monitor.pack(side=tk.LEFT, padx=5)

        self.btn_quarantine = tk.Button(btn_frame, text="📦 Карантин", command=self.show_quarantine,
                                        bg='#1e1e1e', fg='#00ff00', width=20, height=2, font=('Consolas', 11))
        self.btn_quarantine.pack(side=tk.LEFT, padx=5)

        self.btn_settings = tk.Button(btn_frame, text="⚙️ Налаштування", command=self.show_settings,
                                      bg='#1e1e1e', fg='#00ff00', width=20, height=2, font=('Consolas', 11))
        self.btn_settings.pack(side=tk.LEFT, padx=5)

        self.progress = ttk.Progressbar(self.root, mode='indeterminate', length=600)
        self.progress.pack(pady=5)

        self.log_text = scrolledtext.ScrolledText(self.root, width=130, height=38,
                                                   bg='#0f0f0f', fg='#00ff00',
                                                   insertbackground='white',
                                                   font=('Consolas', 9))
        self.log_text.pack(pady=10, padx=10, fill=tk.BOTH, expand=True)

        self.log_text.tag_config('error', foreground='#ff5555')
        self.log_text.tag_config('warning', foreground='#ffaa00')
        self.log_text.tag_config('success', foreground='#55ff55')
        self.log_text.tag_config('info', foreground='#55aaff')
        self.log_text.tag_config('critical', foreground='#ff0000', font=('Consolas', 11, 'bold'))

    def log(self, msg, tag=None):
        self.log_text.insert(tk.END, msg + "\n", tag)
        self.log_text.see(tk.END)
        self.root.update()

    def analyze_file(self):
        file_path = filedialog.askopenfilename()
        if file_path:
            self.progress.start()
            threading.Thread(target=self._analyze_file, args=(file_path,), daemon=True).start()

    def _analyze_file(self, file_path):
        try:
            self.log(f"\n[🔍] АНАЛІЗ ФАЙЛУ: {file_path}", 'info')
            static = scanner.static_analysis(file_path)
            self.log(f"   MD5: {static['md5']}", 'info')
            self.log(f"   SHA256: {static['sha256']}", 'info')
            self.log(f"   Тип: {static['file_type']}", 'info')
            self.log(f"   Розмір: {static['size']} байт", 'info')
            self.log(f"   Ентропія: {static['entropy']:.2f}", 'info')
            self.log(f"   YARA знахідок: {len(static['yara_matches'])}", 'warning' if static['yara_matches'] else 'info')
            for m in static['yara_matches']:
                self.log(f"      - {m}", 'warning')

            if static['suspicious_functions']:
                self.log(f"   Підозрілі функції: {len(static['suspicious_functions'])}", 'warning')
                for f in static['suspicious_functions'][:10]:
                    self.log(f"      - {f}", 'warning')

            if static['scripts']:
                self.log(f"   Скриптові індикатори: {len(static['scripts'])}", 'warning')
            if static['office']:
                self.log(f"   Макроси офісних документів: {len(static['office'])}", 'warning')
            if static['pdf']:
                self.log(f"   Підозрілі PDF-елементи: {len(static['pdf'])}", 'warning')
            if static['archive']:
                self.log(f"   Архів містить файлів: {len(static['archive'])}", 'info')
            if static['apk']:
                self.log(f"   APK-підозри: {len(static['apk'])}", 'warning')

            # Хмарна перевірка
            cloud_result = self.cloud.check_hash(static['md5'])
            if cloud_result:
                self.log("   ☁️ VirusTotal: виявлено загрозу!", 'error')
                static['threat_score'] += 30
            elif cloud_result is False:
                self.log("   ☁️ VirusTotal: чисто", 'success')

            # Пісочниця
            sandbox_result = self.sandbox.analyze(file_path)
            if sandbox_result['suspicious_api']:
                self.log("   🧪 Пісочниця: виявлено підозрілі API", 'warning')

            self.log(f"\n   📊 ПІДСУМКОВИЙ БАЛ: {static['threat_score']}/100", 'critical' if static['threat_score'] > 70 else 'error' if static['threat_score'] > 50 else 'success')

            if static['threat_score'] > 50:
                self.log("   ❌ ВИЯВЛЕНО ЗАГРОЗУ!", 'error')
                if messagebox.askyesno("Загроза", "Помістити файл у карантин?"):
                    quarantine.move_to_quarantine(file_path)
                    self.log("   ✅ Файл у карантині", 'success')
            else:
                self.log("   ✅ ЗАГРОЗ НЕ ВИЯВЛЕНО", 'success')

            report_path = report.save_scan_report(static)
            self.log(f"   📁 Звіт: {report_path}", 'info')

        except Exception as e:
            self.log(f"❌ ПОМИЛКА: {str(e)}", 'error')
        finally:
            self.progress.stop()

    def analyze_dir(self):
        dir_path = filedialog.askdirectory()
        if dir_path:
            self.progress.start()
            threading.Thread(target=self._analyze_dir, args=(dir_path,), daemon=True).start()

    def _analyze_dir(self, dir_path):
        try:
            self.log(f"\n[🔍] СКАНУВАННЯ ТЕКИ: {dir_path}", 'info')
            results = []
            for root, dirs, files in os.walk(dir_path):
                for file in files:
                    file_path = os.path.join(root, file)
                    try:
                        res = scanner.static_analysis(file_path)
                        results.append(res)
                        if res['threat_score'] > 50:
                            self.log(f"   [⚠️] {file_path} (бал {res['threat_score']})", 'warning')
                    except Exception as e:
                        self.log(f"   ❌ Помилка сканування {file_path}: {e}", 'error')
            threats = [r for r in results if r['threat_score'] > 50]
            self.log(f"\n📊 Проскановано файлів: {len(results)}", 'info')
            self.log(f"🚨 Виявлено загроз: {len(threats)}", 'error' if threats else 'success')
            report.save_directory_report(results)
        except Exception as e:
            self.log(f"❌ ПОМИЛКА: {str(e)}", 'error')
        finally:
            self.progress.stop()

    def show_behaviors(self):
        behaviors = self.monitor.get_behaviors()
        self.log("\n=== 👁️ ПІДОЗРІЛА ПОВЕДІНКА ПРОЦЕСІВ ===", 'info')
        if not behaviors:
            self.log("   Немає підозрілої активності", 'success')
        else:
            for b in behaviors[-20:]:
                self.log(f"   [{b['time'].strftime('%H:%M:%S')}] {b['process']} (PID {b['pid']}): {b['type']} - {b.get('cmdline', b.get('remote', ''))}", 'warning')

    def show_quarantine(self):
        files = quarantine.list_quarantine()
        self.log("\n=== 📦 КАРАНТИН ===", 'info')
        if files:
            for f in files:
                self.log(f"   {f}", 'info')
        else:
            self.log("   Карантин порожній", 'success')

    def show_settings(self):
        # Прості налаштування (можна розширити)
        settings_win = tk.Toplevel(self.root)
        settings_win.title("Налаштування")
        settings_win.geometry("400x300")
        settings_win.configure(bg='#1e1e1e')
        tk.Label(settings_win, text="Поріг виявлення:", bg='#1e1e1e', fg='white').pack(pady=5)
        threshold_var = tk.IntVar(value=config.THRESHOLD_MEDIUM)
        tk.Scale(settings_win, from_=0, to=100, orient=tk.HORIZONTAL, variable=threshold_var).pack()
        tk.Button(settings_win, text="Зберегти", command=lambda: self.save_settings(threshold_var.get())).pack(pady=10)

    def save_settings(self, threshold):
        config.THRESHOLD_MEDIUM = threshold
        self.log(f"⚙️ Поріг виявлення змінено на {threshold}", 'info')

if __name__ == "__main__":
    root = tk.Tk()
    app = UltimateAVApp(root)
    root.mainloop()
