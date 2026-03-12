import os
import pefile
import lief
from . import utils, yara_rules, config

# ========== АНАЛІЗ PE ==========
def analyze_pe(file_path):
    result = {'functions': [], 'sections': [], 'exports': [], 'resources': []}
    try:
        pe = pefile.PE(file_path)
        # Імпорти
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                for imp in entry.imports:
                    if imp.name:
                        result['functions'].append(imp.name.decode())
        # Експорти
        if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
            for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                if exp.name:
                    result['exports'].append(exp.name.decode())
        # Секції
        for section in pe.sections:
            name = section.Name.decode().rstrip('\x00')
            data = section.get_data()
            entropy = utils.calculate_entropy(data)
            result['sections'].append({'name': name, 'entropy': entropy})
        # Ресурси
        if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
            result['resources'] = ['found']
    except:
        pass
    return result

# ========== АНАЛІЗ ELF ==========
def analyze_elf(file_path):
    result = {'functions': [], 'sections': []}
    try:
        binary = lief.parse(file_path)
        if binary:
            for section in binary.sections:
                result['sections'].append(section.name)
            for symbol in binary.symbols:
                result['functions'].append(symbol.name)
    except:
        pass
    return result

# ========== АНАЛІЗ MACH-O ==========
def analyze_macho(file_path):
    result = {'functions': [], 'sections': []}
    try:
        binary = lief.parse(file_path)
        if binary:
            for section in binary.sections:
                result['sections'].append(section.name)
            for symbol in binary.symbols:
                result['functions'].append(symbol.name)
    except:
        pass
    return result

# ========== АНАЛІЗ СКРИПТІВ ==========
def analyze_script(file_path):
    suspicious = []
    try:
        with open(file_path, 'r', errors='ignore') as f:
            content = f.read().lower()
            patterns = [
                ('powershell -e', 'encoded command'),
                ('invoke-expression', 'eval'),
                ('downloadstring', 'web download'),
                ('winhttp', 'http'),
                ('socket', 'socket'),
                ('createobject', 'com object'),
                ('wscript.shell', 'shell'),
                ('shell.application', 'shell'),
                ('msxml2.xmlhttp', 'http'),
                ('base64', 'base64'),
                ('bypass', 'bypass'),
                ('hidden', 'hidden window'),
                ('iex', 'invoke expression'),
                ('start-process', 'run process'),
                ('add-mppreference', 'defender bypass'),
                ('set-mppreference', 'defender bypass'),
                ('disable realtime', 'disable monitoring'),
            ]
            for pat, desc in patterns:
                if pat in content:
                    suspicious.append(desc)
    except:
        pass
    return suspicious

# ========== АНАЛІЗ ОФІСНИХ ДОКУМЕНТІВ ==========
def analyze_office(file_path):
    suspicious = []
    try:
        from oletools.olevba import VBA_Parser
        vbaparser = VBA_Parser(file_path)
        if vbaparser.detect_vba_macros():
            suspicious.append('VBA macros detected')
            for (filename, stream_path, vba_filename, vba_code) in vbaparser.extract_macros():
                if 'AutoOpen' in vba_code or 'Document_Open' in vba_code:
                    suspicious.append('Auto-exec macro')
                if 'Shell' in vba_code or 'CreateObject' in vba_code:
                    suspicious.append('Suspicious VBA functions')
    except:
        pass
    return suspicious

# ========== АНАЛІЗ PDF ==========
def analyze_pdf(file_path):
    suspicious = []
    try:
        import PyPDF2
        with open(file_path, 'rb') as f:
            pdf = PyPDF2.PdfReader(f)
            if '/JavaScript' in pdf.trailer.get('/Root', {}) or '/JS' in pdf.trailer.get('/Root', {}):
                suspicious.append('JavaScript in PDF')
            if '/OpenAction' in pdf.trailer.get('/Root', {}):
                suspicious.append('OpenAction - auto-execute')
            if '/Launch' in pdf.trailer.get('/Root', {}):
                suspicious.append('Launch action')
    except:
        pass
    return suspicious

# ========== АНАЛІЗ АРХІВІВ ==========
def analyze_archive(file_path):
    contents = []
    try:
        import zipfile, rarfile, py7zr
        if zipfile.is_zipfile(file_path):
            with zipfile.ZipFile(file_path, 'r') as z:
                contents = z.namelist()
        elif rarfile.is_rarfile(file_path):
            with rarfile.RarFile(file_path) as r:
                contents = r.namelist()
        elif file_path.endswith('.7z'):
            with py7zr.SevenZipFile(file_path, 'r') as sz:
                contents = sz.getnames()
    except:
        pass
    return contents

# ========== АНАЛІЗ APK ==========
def analyze_apk(file_path):
    suspicious = []
    try:
        import zipfile
        with zipfile.ZipFile(file_path, 'r') as z:
            if 'AndroidManifest.xml' in z.namelist():
                manifest = z.read('AndroidManifest.xml')
                dangerous = [b'READ_SMS', b'SEND_SMS', b'RECORD_AUDIO', b'CAMERA', b'ACCESS_FINE_LOCATION']
                for perm in dangerous:
                    if perm in manifest:
                        suspicious.append(f'Dangerous permission: {perm.decode()}')
    except:
        pass
    return suspicious

# ========== СТАТИЧНИЙ АНАЛІЗ ФАЙЛУ ==========
def static_analysis(file_path):
    md5, sha1, sha256 = utils.get_file_hashes(file_path)
    result = {
        'file_path': file_path,
        'md5': md5,
        'sha1': sha1,
        'sha256': sha256,
        'file_type': utils.get_file_type(file_path),
        'size': utils.get_file_size(file_path),
        'entropy': 0,
        'yara_matches': [],
        'pe_info': None,
        'elf_info': None,
        'macho_info': None,
        'scripts': [],
        'office': [],
        'pdf': [],
        'archive': [],
        'apk': [],
        'suspicious_functions': [],
        'threat_score': 0
    }

    with open(file_path, 'rb') as f:
        data = f.read()
    result['entropy'] = utils.calculate_entropy(data)

    # YARA
    if yara_rules.yara_rules:
        matches = yara_rules.yara_rules.match(data=data)
        result['yara_matches'] = [m.rule for m in matches]
        result['threat_score'] += len(result['yara_matches']) * 10

    # Визначаємо тип файлу за розширенням та аналізуємо відповідно
    ext = file_path.lower()
    if ext.endswith(('.exe', '.dll', '.sys')):
        pe_info = analyze_pe(file_path)
        result['pe_info'] = pe_info
        result['suspicious_functions'] = pe_info.get('functions', [])
        result['threat_score'] += len(result['suspicious_functions']) * 2
        for sec in pe_info.get('sections', []):
            if sec['entropy'] > config.ENTROPY_THRESHOLD:
                result['threat_score'] += 10
    elif ext.endswith('.elf'):
        elf_info = analyze_elf(file_path)
        result['elf_info'] = elf_info
    elif ext.endswith(('.dylib', '.so')):
        macho_info = analyze_macho(file_path)
        result['macho_info'] = macho_info
    elif ext.endswith(('.ps1', '.vbs', '.js', '.bat', '.cmd')):
        result['scripts'] = analyze_script(file_path)
        result['threat_score'] += len(result['scripts']) * 10
    elif ext.endswith(('.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx', '.docm', '.xlsm', '.pptm')):
        result['office'] = analyze_office(file_path)
        result['threat_score'] += len(result['office']) * 15
    elif ext.endswith('.pdf'):
        result['pdf'] = analyze_pdf(file_path)
        result['threat_score'] += len(result['pdf']) * 15
    elif ext.endswith(('.zip', '.rar', '.7z', '.tar', '.gz')):
        result['archive'] = analyze_archive(file_path)
        result['threat_score'] += len(result['archive']) // 10
    elif ext.endswith('.apk'):
        result['apk'] = analyze_apk(file_path)
        result['threat_score'] += len(result['apk']) * 5

    # Евристика: висока ентропія
    if result['entropy'] > config.ENTROPY_THRESHOLD:
        result['threat_score'] += 30

    # Якщо є підозрілі функції зі списку
    sus_funcs = [f for f in result['suspicious_functions'] if f in config.SUSPICIOUS_API_LIST]
    result['threat_score'] += len(sus_funcs) * 3

    return result
