"""Xác thực giấy phép offline bằng chữ ký số Ed25519. Không chứa khóa bí mật."""
import base64, hashlib, json, os, re, uuid
from datetime import date
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

PUBLIC_KEY_HEX = "2c3a360b93ef62434edb1fff5b49e1044bc023a89d68183443e509c978152888"
PRODUCT = "Auto Train Mil va Co Mo 4NV"

def hwid():
    try:
        import winreg
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r'SOFTWARE\Microsoft\Cryptography', 0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY) as k:
            machine_id = str(winreg.QueryValueEx(k, 'MachineGuid')[0])
    except (OSError, ImportError):
        machine_id = str(uuid.getnode())
    digest = hashlib.sha256((PRODUCT + ':' + machine_id).encode()).hexdigest().upper()[:32]
    return '-'.join(digest[i:i+8] for i in range(0, 32, 8))

def license_file():
    path = Path(os.environ.get('LOCALAPPDATA', str(Path.home()))) / 'AutoTrainMilCoMo4NV'
    path.mkdir(parents=True, exist_ok=True)
    return path / 'license.txt'

def validate(token):
    try:
        part, sig = token.strip().split('.')
        decode = lambda s: base64.urlsafe_b64decode(s + '=' * (-len(s) % 4))
        raw = decode(part)
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(PUBLIC_KEY_HEX)).verify(decode(sig), raw)
        payload = json.loads(raw)
    except Exception as exc:
        raise ValueError('Mã kích hoạt không hợp lệ hoặc đã bị thay đổi.') from exc
    if payload.get('product') != PRODUCT or payload.get('hwid') != hwid():
        raise ValueError('Mã kích hoạt không dành cho máy tính này.')
    if payload.get('type') == 'lifetime':
        return 'Vĩnh viễn'
    try:
        expiry = date.fromisoformat(payload['expires'])
    except (KeyError, ValueError, TypeError) as exc:
        raise ValueError('Mã kích hoạt thiếu hạn sử dụng.') from exc
    if date.today() > expiry:
        raise ValueError('Mã đã hết hạn ngày ' + expiry.strftime('%d/%m/%Y'))
    return 'Hết hạn ' + expiry.strftime('%d/%m/%Y')

def check_saved():
    try:
        return validate(license_file().read_text(encoding='utf-8').strip())
    except (OSError, ValueError):
        return None
