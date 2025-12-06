import os
import pyodbc
from azure.storage.blob import BlobServiceClient

# Azure SQL Connection
server = 'acucognsqlserver.database.windows.net'
database = 'ambientscribe_sql'
username = 'adminuser'
password = 'Keyisthepassword@7'
driver = '{ODBC Driver 17 for SQL Server}'

conn_str = f"""
    DRIVER={driver};
    SERVER={server};
    DATABASE={database};
    UID={username};
    PWD={password};
    Encrypt=yes;
    TrustServerCertificate=no;
    Connection Timeout=30;
"""

# Azure Blob Storage Connection
blob_service_client = BlobServiceClient.from_connection_string(
    os.getenv("AZURE_STORAGE_CONNECTION_STRING")
)