import os
import re
import io
import json
import httpx
import argparse

from urllib.parse import urljoin
from urllib3.filepost import choose_boundary
from httpx import Response

from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.http import MediaIoBaseDownload

from .file_utils import format_print_path, check_for_ignore


SCOPES = [
    "https://www.googleapis.com/auth/drive",
    "https://www.googleapis.com/auth/drive.file",
    "https://www.googleapis.com/auth/drive.metadata",
]
DRIVE_API_BASE_URL = "https://www.googleapis.com/upload/drive/v3/"
FILE_SIZE_THRESHOLD = 5 * 1024**2
client_secrets_file = "client_secrets.json"
token_file = "token.json"

# pattern search variables
include_pattern = None
ignore_pattern = None
include_over_ignore = True


def check_for_error(resp: Response):
    if resp.status_code >= 300:
        raise Exception(resp.content.decode())


def authenticate():
    creds = None
    if os.path.exists(token_file):
        creds = Credentials.from_authorized_user_file(token_file, SCOPES)
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file(
                client_secrets_file, SCOPES
            )
            creds = flow.run_local_server()
            with open(token_file, "w") as writer:
                writer.write(creds.to_json())
    return creds


def upload(file_path: str, parent_id: str):
    creds = authenticate()
    authorization_headers = {"Authorization": "Bearer {}".format(creds.token)}
    service = build("drive", "v3", credentials=creds)

    print("Scanning...")
    file_path = os.path.abspath(file_path)
    stack = [file_path]
    sequence = []
    while stack:
        f = stack.pop()
        if check_for_ignore(
            f,
            ignore_pattern=ignore_pattern,
            include_pattern=include_pattern,
            include_over_ignore=include_over_ignore,
        ):
            continue
        sequence.append(f)
        if os.path.isdir(f):
            subpaths = os.listdir(f)
            subpaths = [os.path.join(f, p) for p in subpaths]
            subpaths = [p for p in subpaths if os.path.isfile(p) or os.path.isdir(p)]
            stack.extend(subpaths)

    print("Uploading...")
    id_tracker = {}
    count = len(sequence)
    max_num_width = len(str(count))
    counter_prefix_template = "#File {:0%d}/{}" % max_num_width
    drive_api_file_endpoint = urljoin(DRIVE_API_BASE_URL, "files")
    iterating_status = ""

    with httpx.Client(timeout=60) as client:
        for i, f in enumerate(sequence):
            counter_prefix = counter_prefix_template.format(i + 1, count)
            flush_string = "\r" + " " * len(iterating_status) + "\r"
            iterating_status = "{}: {}".format(
                counter_prefix, format_print_path(f, max_line_len=150)
            )
            print(flush_string + iterating_status, end="")
            f_dir = os.path.dirname(f)
            _parent = id_tracker.get(f_dir, parent_id)
            if os.path.isfile(f):
                file_size = os.path.getsize(f)
                with open(f, "rb") as reader:
                    file_content = reader.read()
                file_metadata = {"name": os.path.basename(f), "parents": [_parent]}
                if file_size < FILE_SIZE_THRESHOLD:  # multipart upload
                    boundary = choose_boundary()
                    encoded_boundary = boundary.encode()
                    headers = {
                        "Content-Type": 'multipart/related; boundary="{}"'.format(
                            boundary
                        )
                    }
                    body = b""
                    body += b"--" + encoded_boundary + b"\n"
                    body += b"Content-Type: application/json; charset=UTF-8\n\n"
                    body += json.dumps(file_metadata).encode() + b"\n"
                    body += b"--" + encoded_boundary + b"\n"
                    body += b"Content-Type: application/octet-stream\n\n"
                    body += file_content + b"\n"
                    body += b"--" + encoded_boundary + b"--"
                    resp = client.post(
                        drive_api_file_endpoint,
                        content=body,
                        headers={**headers, **authorization_headers},
                    )
                    check_for_error(resp)
                else:  # use resumable upload
                    resp = client.post(
                        drive_api_file_endpoint,
                        params={"uploadType": "resumable"},
                        json=file_metadata,
                        headers={
                            "Content-Type": "application/json; charset=UTF-8",
                            **authorization_headers,
                        },
                    )
                    check_for_error(resp)
                    session_uri = resp.headers.get("location")
                    bytes_sent = 0
                    chunk_size = FILE_SIZE_THRESHOLD
                    while True:
                        chunk = file_content[bytes_sent : bytes_sent + chunk_size]
                        if len(chunk) == 0:
                            break
                        resp = client.put(
                            session_uri,
                            content=chunk,
                            headers={
                                **{
                                    "Content-Length": str(len(chunk)),
                                    "Content-Range": "bytes {}-{}/{}".format(
                                        bytes_sent,
                                        bytes_sent + len(chunk) - 1,
                                        file_size,
                                    ),
                                },
                                **authorization_headers,
                            },
                        )
                        if resp.status_code < 300:
                            break
                        elif resp.status_code == 308:
                            sent_range = resp.headers.get("range", "")
                            match = re.match(
                                r"^bytes=\d+-(?P<last_byte>\d+)$", sent_range
                            )
                            if not match:
                                raise Exception("Cannot determine bytes range")
                            bytes_sent = int(match.group("last_byte")) + 1
                            flush_string = "\r" + " " * len(iterating_status) + "\r"
                            iterating_status = "{} ({}): {}".format(
                                counter_prefix,
                                "{}/{}".format(bytes_sent, file_size),
                                format_print_path(f),
                            )
                            print(flush_string + iterating_status, end="")
                        else:
                            raise Exception(resp.content.decode())
            else:
                file_metadata = {
                    "name": os.path.basename(f),
                    "parents": [_parent],
                    "mimeType": "application/vnd.google-apps.folder",
                }
                uploaded_folder = (
                    service.files().create(body=file_metadata, fields="id").execute()
                )
                id_tracker[f] = uploaded_folder.get("id")

        # end loop, print newline
        print()


def list_files_in_folder(service, folder_id):
    files = []
    page_token = None
    while True:
        response = (
            service.files()
            .list(
                q=f"'{folder_id}' in parents",
                spaces="drive",
                fields="nextPageToken, files(id, name, mimeType)",
                pageToken=page_token,
            )
            .execute()
        )
        files.extend(response.get("files", []))
        page_token = response.get("nextPageToken", None)
        if page_token is None:
            break
    return files


def download_folder(service, folder_id, folder_name, save_path):
    folder_path = os.path.join(save_path, folder_name)
    if not os.path.exists(folder_path):
        os.makedirs(folder_path)
    items = list_files_in_folder(service, folder_id)
    for item in items:
        if item["mimeType"] == "application/vnd.google-apps.folder":
            download_folder(service, item["id"], item["name"], folder_path)
        else:
            download_file(service, item["id"], item["name"], folder_path)


def download_file(service, file_id, file_name, save_path):
    request = service.files().get_media(fileId=file_id)
    file_path = os.path.join(save_path, file_name)
    print("Downloading to {}...".format(file_path))
    file = io.FileIO(file_path, "wb")
    downloader = MediaIoBaseDownload(file, request)
    done = False
    progress = ""
    while done is False:
        status, done = downloader.next_chunk()
        flush_string = "\r" + " " * len(progress) + "\r"
        progress = f"Downloaded {int(status.progress() * 100)}%"
        print(flush_string + progress, end="")
    print()


def download(file_id: str, download_dir: str):
    creds = authenticate()

    # create drive api client
    service = build("drive", "v3", credentials=creds)
    file_metadata = (
        service.files().get(fileId=file_id, fields="name,mimeType").execute()
    )

    if file_metadata["mimeType"] == "application/vnd.google-apps.folder":
        download_folder(service, file_id, file_metadata["name"], download_dir)
    else:
        download_file(service, file_id, file_metadata["name"], download_dir)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "command",
        choices=["up", "down"],
        help="What action do you want to perform? Upload or download?",
    )
    parser.add_argument(
        "--file_id",
        help="Id of the file or folder on Google Drive. Required if `command` is `down`",
    )
    parser.add_argument(
        "--download_dir",
        default=None,
        help="Path where the downloaded file will be locate. Default to the current directory.",
    )
    parser.add_argument(
        "--file_path",
        "-f",
        help="Path to the file or directory that you want to upload. Required if `command` is `up`",
    )
    parser.add_argument(
        "--client_secrets_file",
        "-c",
        default="client_secrets.json",
        help="Path to the credentials file, containing the client_id and client_secret.",
    )
    parser.add_argument(
        "--token_file",
        "-t",
        default="token.json",
        help="Path to the token file, containing the access_token and the refresh_token",
    )
    parser.add_argument(
        "--parent_id",
        default="root",
        help="ID of the directory that will contain the file to upload.",
    )
    parser.add_argument(
        "--ignore_pattern",
        nargs="+",
        default=None,
        help="Exclude files matching this pattern.",
    )
    parser.add_argument(
        "--include_pattern",
        nargs="+",
        default=None,
        help="Include files matching this pattern.",
    )
    parser.add_argument(
        "--include_over_ignore",
        default=True,
        type=eval,
        help="If True, files not matching `ignore_pattern` or matching `include_pattern` will be included. "
        "Else, files matching `include_pattern` and not matching `ignore_pattern` will be included.",
    )
    args = parser.parse_args()

    global include_pattern, ignore_pattern, include_over_ignore, client_secrets_file, token_file
    token_file = args.token_file
    include_pattern = args.include_pattern
    ignore_pattern = args.ignore_pattern
    include_over_ignore = args.include_over_ignore

    # list_files_in_folder()
    if args.command == "up":
        upload(args.file_path, args.parent_id)
    else:
        download(args.file_id, args.download_dir or os.getcwd())


if __name__ == "__main__":
    main()
