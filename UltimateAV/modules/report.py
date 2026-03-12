import json
import os
from datetime import datetime
from . import config

def save_scan_report(scan_result):
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"report_{timestamp}.txt"
    filepath = os.path.join(config.REPORTS_DIR, filename)

    with open(filepath, 'w', encoding='utf-8') as f:
        f.write("="*70 + "\n")
        f.write("🔥 АНТИВІРУС - ЗВІТ ПРО АНАЛІЗ\n")
        f.write(f"Час: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write("="*70 + "\n\n")
        f.write(f"📁 Файл: {scan_result.get('file_path', 'N/A')}\n")
        f.write(f"🔑 MD5: {scan_result.get('md5', 'N/A')}\n")
        f.write(f"🔑 SHA1: {scan_result.get('sha1', 'N/A')}\n")
        f.write(f"🔐 SHA256: {scan_result.get('sha256', 'N/A')}\n")
        f.write(f"📦 Тип: {scan_result.get('file_type', 'N/A')}\n")
        f.write(f"📏 Розмір: {scan_result.get('size', 0)} байт\n")
        f.write(f"📊 Ентропія: {scan_result.get('entropy', 0):.2f}\n")
        f.write(f"⚠️ Рівень загрози: {scan_result.get('threat_score', 0)}/100\n")
        f.write(f"🚨 Загроза: {'ТАК' if scan_result.get('threat_score', 0) > 50 else 'НІ'}\n\n")

        if scan_result.get('yara_matches'):
            f.write("YARA знахідки:\n")
            for m in scan_result['yara_matches']:
                f.write(f"  - {m}\n")
            f.write("\n")

        if scan_result.get('suspicious_functions'):
            f.write("Підозрілі функції:\n")
            for fn in scan_result['suspicious_functions'][:20]:
                f.write(f"  - {fn}\n")
            f.write("\n")

        if scan_result.get('scripts'):
            f.write("Скрипти/макроси:\n")
            for s in scan_result['scripts']:
                f.write(f"  - {s}\n")
            f.write("\n")

        if scan_result.get('office'):
            f.write("Макроси офісних документів:\n")
            for o in scan_result['office']:
                f.write(f"  - {o}\n")
            f.write("\n")

        if scan_result.get('pdf'):
            f.write("PDF:\n")
            for p in scan_result['pdf']:
                f.write(f"  - {p}\n")
            f.write("\n")

        if scan_result.get('archive'):
            f.write("Архів містить:\n")
            for a in scan_result['archive'][:20]:
                f.write(f"  - {a}\n")
            f.write("\n")

        f.write("="*70 + "\n")

    json_file = filepath.replace('.txt', '.json')
    with open(json_file, 'w', encoding='utf-8') as f:
        json.dump(scan_result, f, indent=2, ensure_ascii=False)
    return filepath

def save_directory_report(results):
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"dir_report_{timestamp}.txt"
    filepath = os.path.join(config.REPORTS_DIR, filename)

    threats = [r for r in results if r.get('threat_score', 0) > 50]

    with open(filepath, 'w', encoding='utf-8') as f:
        f.write("="*70 + "\n")
        f.write("📂 ЗВІТ СКАНУВАННЯ ТЕКИ\n")
        f.write(f"Час: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write("="*70 + "\n\n")
        f.write(f"📊 Проскановано файлів: {len(results)}\n")
        f.write(f"🚨 Виявлено загроз: {len(threats)}\n\n")
        if threats:
            f.write("❌ ЗАГРОЗИ:\n")
            for t in threats[:50]:
                f.write(f"  - {t['file_path']} (рівень {t['threat_score']})\n")
        else:
            f.write("✅ Загроз не виявлено.\n")
    return filepath
