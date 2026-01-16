#!/usr/bin/env python3
"""
Проверка лицензионного ключа.
"""

import hashlib
import sys


def verify(license_key: str, expected_hash: str = None) -> bool:
    """Проверяет валидность ключа."""
    calculated_hash = hashlib.sha256(license_key.encode()).hexdigest()
    
    print(f"Ключ: {license_key}")
    print(f"Хэш: {calculated_hash}")
    
    if expected_hash:
        if calculated_hash == expected_hash:
            print("✅ Ключ валиден!")
            return True
        else:
            print("❌ Хэш не совпадает!")
            return False
    
    return True


def main():
    if len(sys.argv) < 2:
        print("Использование: python verify_license.py <LICENSE_KEY> [EXPECTED_HASH]")
        print("Пример: python verify_license.py WAFKEY123")
        sys.exit(1)
    
    license_key = sys.argv[1]
    expected_hash = sys.argv[2] if len(sys.argv) > 2 else None
    
    verify(license_key, expected_hash)


if __name__ == "__main__":
    main()
