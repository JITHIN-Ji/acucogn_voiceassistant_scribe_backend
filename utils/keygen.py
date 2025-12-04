"""Utility to generate a secure base64-encoded 32-byte AES key for `AES256_KEY` env var.

Usage (PowerShell):
  python -m backend.utils.keygen

Copy the printed value into your environment or `.env` file as `AES256_KEY`.
"""
import base64
import os


def generate_key() -> str:
    key = os.urandom(32)
    return base64.b64encode(key).decode('utf-8')


def main() -> None:
    print(generate_key())


if __name__ == '__main__':
    main()
