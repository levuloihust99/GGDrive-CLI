import os
import re
import io
import json
import httpx
import argparse
from typing import Optional, Union

from urllib.parse import urljoin
from urllib3.filepost import choose_boundary
from httpx import Response

from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.http import MediaIoBaseDownload

from .file_utils import format_print_path, list_files


SCOPES = [
    "https://www.googleapis.com/auth/drive",
    "https://www.googleapis.com/auth/drive.file",
    "https://www.googleapis.com/auth/drive.metadata",
]
DRIVE_API_BASE_URL = "https://www.googleapis.com/upload/drive/v3/"
DRIVE_API_FILE_ENDPOINT = urljoin(DRIVE_API_BASE_URL, "files")
FILE_SIZE_THRESHOLD = 5 * 1024**2
CREDS = {"value": None}
SERVICE = {"value": None}

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


def get_creds():
    if not CREDS["value"]:
        CREDS["value"] = authenticate()
    creds = CREDS["value"]
    return creds


def get_service():
    if not SERVICE["value"]:
        creds = get_creds()
        SERVICE["value"] = build("drive", "v3", credentials=creds)
    return SERVICE["value"]


def make_request(
    url: str,
    method: str,
    client: Optional[httpx.Client] = None,
    params: Optional[dict] = None,
    content: Optional[bytes] = None,
    json_data: Optional[Union[list, dict]] = None,
    headers: Optional[dict] = None,
):
    kwargs = {}
    if params is not None:
        kwargs.update(params=params)
    if content is not None:
        kwargs.update(content=content)
    if json_data is not None:
        kwargs.update(json=json_data)
    if headers is not None:
        kwargs.update(headers=headers)
    if client:
        resp = client.request(method=method, url=url, **kwargs)
    else:
        with httpx.Client(timeout=60) as client:
            resp = client.request(method=method, url=url, **kwargs)
    return resp


def upload_single(
    file_path: str,
    parent_id: str,
    client: Optional[httpx.Client] = None,
    id_tracker: Optional[dict] = None,
    iterating_status_tracker: Optional[str] = None,
    prefix: Optional[str] = "File",
):
    creds = get_creds()
    authorization_headers = {"Authorization": "Bearer {}".format(creds.token)}
    service = get_service()

    if isinstance(iterating_status_tracker, dict):
        iterating_status = iterating_status_tracker.get("value", "")
    else:
        iterating_status = ""
    flush_string = "\r" + " " * len(iterating_status) + "\r"
    iterating_status = "{}: {}".format(
        prefix, format_print_path(file_path, max_line_len=150)
    )
    print(flush_string + iterating_status, end="")
    if isinstance(iterating_status_tracker, dict):
        iterating_status_tracker["value"] = iterating_status

    if os.path.isfile(file_path):
        file_size = os.path.getsize(file_path)
        with open(file_path, "rb") as reader:
            file_content = reader.read()
        file_metadata = {"name": os.path.basename(file_path), "parents": [parent_id]}
        if file_size < FILE_SIZE_THRESHOLD:  # multipart upload
            boundary = choose_boundary()
            encoded_boundary = boundary.encode()
            headers = {
                "Content-Type": 'multipart/related; boundary="{}"'.format(boundary)
            }
            body = b""
            body += b"--" + encoded_boundary + b"\n"
            body += b"Content-Type: application/json; charset=UTF-8\n\n"
            body += json.dumps(file_metadata).encode() + b"\n"
            body += b"--" + encoded_boundary + b"\n"
            body += b"Content-Type: application/octet-stream\n\n"
            body += file_content + b"\n"
            body += b"--" + encoded_boundary + b"--"
            resp = make_request(
                url=DRIVE_API_FILE_ENDPOINT,
                method="post",
                client=client,
                content=body,
                headers={**headers, **authorization_headers},
            )
            check_for_error(resp)
        else:  # use resumable upload
            resp = client.post(
                DRIVE_API_FILE_ENDPOINT,
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
                resp = make_request(
                    url=session_uri,
                    method="put",
                    client=client,
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
                    match = re.match(r"^bytes=\d+-(?P<last_byte>\d+)$", sent_range)
                    if not match:
                        raise Exception("Cannot determine bytes range")
                    bytes_sent = int(match.group("last_byte")) + 1
                    if isinstance(iterating_status_tracker, dict):
                        iterating_status = iterating_status_tracker.get("value", "")
                    else:
                        iterating_status = ""
                    flush_string = "\r" + " " * len(iterating_status) + "\r"
                    iterating_status = "{} ({}): {}".format(
                        prefix,
                        "{}/{}".format(bytes_sent, file_size),
                        format_print_path(file_path),
                    )
                    if isinstance(iterating_status_tracker, dict):
                        iterating_status_tracker["value"] = iterating_status
                    print(flush_string + iterating_status, end="")
                else:
                    raise Exception(resp.content.decode())
    else:
        file_metadata = {
            "name": os.path.basename(file_path),
            "parents": [parent_id],
            "mimeType": "application/vnd.google-apps.folder",
        }
        uploaded_folder = (
            service.files().create(body=file_metadata, fields="id").execute()
        )
        if isinstance(id_tracker, dict):
            id_tracker[file_path] = uploaded_folder.get("id")


def upload(file_path: str, parent_id: str):
    print("Scanning...")
    sequence = list_files(
        file_path,
        ignore_pattern=ignore_pattern,
        include_pattern=include_pattern,
        include_over_ignore=include_over_ignore,
    )

    print("Uploading...")
    id_tracker = {}
    count = len(sequence)
    max_num_width = len(str(count))
    counter_prefix_template = "#File {:0%d}/{}" % max_num_width
    iterating_status_tracker = {}

    with httpx.Client(timeout=60) as client:
        for i, f in enumerate(sequence):
            prefix = counter_prefix_template.format(i + 1, count)
            f_dir = os.path.dirname(f)
            parent_id = id_tracker.get(f_dir, parent_id)
            upload_single(
                file_path=f,
                parent_id=parent_id,
                client=client,
                id_tracker=id_tracker,
                iterating_status_tracker=iterating_status_tracker,
                prefix=prefix,
            )

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
    parser.add_argument(
        "--recursive",
        default=True,
        type=eval,
        help="Whether to upload the folder recursively."
    )
    args = parser.parse_args()

    global include_pattern, ignore_pattern, include_over_ignore, client_secrets_file, token_file
    token_file = args.token_file
    include_pattern = args.include_pattern
    ignore_pattern = args.ignore_pattern
    include_over_ignore = args.include_over_ignore

    if args.command == "up":
        if args.recursive:
            upload(args.file_path, args.parent_id)
        else:
            upload_single(args.file_path, args.parent_id)
            print()
    else:
        download(args.file_id, args.download_dir or os.getcwd())


if __name__ == "__main__":
    main()
