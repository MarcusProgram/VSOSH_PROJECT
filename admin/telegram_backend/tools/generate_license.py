#!/usr/bin/env python3
import asyncio
import secrets
import string
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from app.db import init_db
from app.licenses import hash_license, insert_license


async def main() -> None:
    await init_db()
    
    key = "".join(secrets.choice(string.ascii_letters + string.digits) for _ in range(24))
    license_hash = hash_license(key)
    await insert_license(license_hash)
    
    print("")
    print("=" * 50)
    print(f"license_key  = {key}")
    print(f"license_hash = {license_hash}")
    print("=" * 50)
    print("")
    print(f"1. /activate {key}")
    print(f"2. WAF_LICENSE_KEY_HASH={license_hash}")
    print("")


if __name__ == "__main__":
    asyncio.run(main())
