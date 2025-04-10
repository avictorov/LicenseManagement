import time
import os
import uuid
import hashlib
import hmac
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Protocol.KDF import PBKDF2
import wmi


# Конфигурация
SECRET_KEY = b'my_super_secret_key_123!'  # Должен храниться в безопасности!
APP_NAME = "MyApp"


def get_hwid():
    """Генерация HWID на основе MAC-адреса и серийного номера диска"""
    try:
        # Получение MAC-адреса
        mac = uuid.getnode()
        mac_str = ':'.join(['{:02X}'.format((mac >> elements) & 0xff) for elements in range(0,8*6,8)][::-1])
        print("Считали MAC : ", mac_str)
        
        # Получение серийного номера диска
        c = wmi.WMI()
        disk_serial = c.Win32_DiskDrive()[0].SerialNumber.strip()
        print("Считали s/n диска : ", disk_serial)
        # Комбинирование и хеширование
        hwid_data = f"{mac_str}-{disk_serial}".encode()
        return hashlib.sha256(hwid_data).digest().hex()
    except Exception as e:
        print(f"Ошибка генерации HWID: {e}")
        return None

def generate_license_key(hwid):
    """Генерация лицензионного ключа с использованием HMAC"""
    hmac_obj = hmac.new(SECRET_KEY, hwid.encode(), hashlib.sha256)
    license_hex = hmac_obj.hexdigest()[:20].upper()
    return '-'.join([license_hex[i:i+5] for i in range(0, 20, 5)])

def encrypt_license(hwid, license_key):
    """Шифрование лицензии с использованием AES-256-CBC"""
    salt = hwid.encode()
    key = PBKDF2(SECRET_KEY, salt, dkLen=32, count=100000)
    cipher = AES.new(key, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(f"{hwid}:{license_key}".encode(), AES.block_size))
    return cipher.iv + ct_bytes

def decrypt_license(encrypted_data, current_hwid):
    """Дешифровка лицензии и проверка целостности"""
    try:
        salt = current_hwid.encode()
        key = PBKDF2(SECRET_KEY, salt, dkLen=32, count=100000)
        iv, ct = encrypted_data[:16], encrypted_data[16:]
        cipher = AES.new(key, AES.MODE_CBC, iv=iv)
        pt = unpad(cipher.decrypt(ct), AES.block_size).decode()
        stored_hwid, license_key = pt.split(':', 1)
        return stored_hwid, license_key
    except Exception as e:
        return None, None

def get_license_path():
    """Путь к файлу лицензии"""
    appdata = os.getenv('APPDATA')
    return os.path.join(appdata, APP_NAME, "license.enc")

def save_license(encrypted_data):
    """Сохранение зашифрованной лицензии"""
    path = get_license_path()
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, 'wb') as f:
        f.write(encrypted_data)
    print("путь к лицензии : ", path)

def load_license():
    """Загрузка лицензии из файла"""
    path = get_license_path()
    if not os.path.exists(path):
        return None
    with open(path, 'rb') as f:
        return f.read()

def activate_license(license_key):
    """Активация лицензии"""
    hwid = get_hwid()
    encrypted_data = encrypt_license(hwid, license_key)
    save_license(encrypted_data)
    print("Активация успешна!")

def check_license():
    """Проверка лицензии при запуске"""
    hwid = get_hwid()
    encrypted_data = load_license()
    
    if not encrypted_data:
        print("Лицензия не найдена!")
        return False

    stored_hwid, stored_key = decrypt_license(encrypted_data, hwid)
    
    if not stored_hwid or stored_hwid != hwid:
        print("Ошибка проверки оборудования!")
        return False
    
    generated_key = generate_license_key(hwid)
    if generated_key != stored_key:
        print("Неверный лицензионный ключ!")
        return False
    
    print("Лицензия действительна")
    return True

# Пример использования
if __name__ == "__main__":
    start_time= time.time()
    # Активация (выполняется один раз)
    path = get_license_path()
    if not os.path.exists(path):
        hwid = get_hwid()
        if hwid:
             license_key = generate_license_key(hwid)
             activate_license(license_key)
        print("Лицензионный ключ : ", license_key)
    # Проверка лицензии
    if check_license():
        print("Приложение запущено")
    else:
        print("Требуется активация")

#Далее имитация кода приложения 
end_time= time.time()
timetaken = end_time - start_time
print("Время выполнения : ", timetaken) # 