"""
Delete ALL data from Azure SQL tables
Use with caution!
"""

import os
import pyodbc
from dotenv import load_dotenv

load_dotenv()

# Load SQL env variables
server = os.getenv('AZURE_SQL_SERVER')
database = os.getenv('AZURE_SQL_DATABASE')
username = os.getenv('AZURE_SQL_USERNAME')
password = os.getenv('AZURE_SQL_PASSWORD')
driver = os.getenv('AZURE_SQL_DRIVER')

# Connection string
conn_str = (
    f"DRIVER={driver};"
    f"SERVER={server};"
    f"DATABASE={database};"
    f"UID={username};"
    f"PWD={password};"
    f"Encrypt=yes;"
    f"TrustServerCertificate=no;"
    f"Connection Timeout=30;"
)

# Tables to clear
tables = [
    "voice_recordings",   # deepest child
    "soap_records",       # child
    "patients",           # child with FK to logged_users
    "logged_users"        # parent table (delete last)
]

print("=" * 60)
print("⚠️  WARNING: THIS WILL DELETE ALL DATA IN THESE TABLES!")
print("=" * 60)
for t in tables:
    print(f"  - {t}")
print("=" * 60)

confirm = input("\nType 'DELETE ALL' to continue: ")

if confirm != "DELETE ALL":
    print("\n❌ Cancelled. No data was deleted.")
    exit()

try:
    print("\n🔌 Connecting to Azure SQL...")
    conn = pyodbc.connect(conn_str)
    cursor = conn.cursor()
    print("✅ Connected!")

    for table in tables:
        print(f"\n🧹 Deleting data from: {table} ...")

        try:
            cursor.execute(f"DELETE FROM [{table}]")
            conn.commit()
            print(f"   ✅ Deleted all rows from {table}")

        except Exception as te:
            print(f"   ❌ Error deleting from {table}: {te}")

    print("\n🎉 All tables cleared successfully!")
    conn.close()

except Exception as e:
    print("\n❌ ERROR: Could not connect to SQL Server")
    print(e)
