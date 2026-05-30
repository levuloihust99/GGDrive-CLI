from urllib.parse import urljoin


SCOPES = [
    "https://www.googleapis.com/auth/drive",
    "https://www.googleapis.com/auth/drive.file",
    "https://www.googleapis.com/auth/drive.metadata",
]
DRIVE_API_BASE_URL = "https://www.googleapis.com/upload/drive/v3/"
DRIVE_API_FILE_ENDPOINT = urljoin(DRIVE_API_BASE_URL, "files")
FILE_SIZE_THRESHOLD = 5 * 1024**2