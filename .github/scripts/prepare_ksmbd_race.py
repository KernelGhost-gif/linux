#!/usr/bin/env python3
"""Apply controlled race-window instrumentation and then the candidate fix."""
from pathlib import Path
import sys

PATH = Path("fs/smb/server/vfs_cache.c")


def replace_once(text, old, new, label):
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{label}: expected one match, found {count}")
    return text.replace(old, new, 1)


def replace_reader(text, body):
    start = text.index("bool ksmbd_app_instance_id_matches(")
    end = text.index("\nstruct ksmbd_file *", start)
    return text[:start] + body.rstrip() + "\n" + text[end:]


def instrument(text):
    if "#include <linux/delay.h>" not in text:
        text = replace_once(
            text,
            "#include <linux/fs.h>\n",
            "#include <linux/fs.h>\n#include <linux/delay.h>\n",
            "delay include",
        )
    reader = r'''bool ksmbd_app_instance_id_matches(struct ksmbd_work *work,
                                   struct ksmbd_file *fp)
{
    bool matches;

    spin_lock(&fp->f_lock);
    if (READ_ONCE(fp->f_state) == FP_INITED && fp->conn && fp->share_conf) {
        pr_info("KSMBD_APP_INSTANCE_RACE_WINDOW\\n");
        udelay(250000);
        matches = !strcmp(fp->share_conf->name, work->tcon->share_conf->name) &&
                  memcmp(fp->conn->ClientGUID, work->conn->ClientGUID,
                         SMB2_CLIENT_GUID_SIZE);
    } else {
        matches = false;
    }
    spin_unlock(&fp->f_lock);

    return matches;
}'''
    return replace_reader(text, reader)


def fix(text):
    reader = r'''bool ksmbd_app_instance_id_matches(struct ksmbd_work *work,
                                   struct ksmbd_file *fp)
{
    struct ksmbd_conn *conn;
    bool matches;

    spin_lock(&fp->f_lock);
    conn = fp->conn;
    if (READ_ONCE(fp->f_state) == FP_INITED && conn && fp->share_conf) {
        pr_info("KSMBD_APP_INSTANCE_RACE_WINDOW\\n");
        udelay(250000);
        matches = !strcmp(fp->share_conf->name, work->tcon->share_conf->name) &&
                  memcmp(conn->ClientGUID, work->conn->ClientGUID,
                         SMB2_CLIENT_GUID_SIZE);
    } else {
        matches = false;
    }
    spin_unlock(&fp->f_lock);

    return matches;
}'''
    text = replace_reader(text, reader)

    old_session = """\twrite_lock(&global_ft.lock);
\tfp->conn = NULL;
\tfp->tcon = NULL;
\tfp->volatile_id = KSMBD_NO_FID;
"""
    new_session = """\twrite_lock(&global_ft.lock);
\tspin_lock(&fp->f_lock);
\tfp->conn = NULL;
\tfp->tcon = NULL;
\tfp->volatile_id = KSMBD_NO_FID;
\tspin_unlock(&fp->f_lock);
"""
    text = replace_once(text, old_session, new_session, "session_fd_check writer")

    old_rebind = """\twrite_lock(&global_ft.lock);
\told_conn = fp->conn;
\tfp->conn = ksmbd_conn_get(work->conn);
\tatomic_inc(&fp->conn->stats.open_files_count);
\tatomic_dec(&old_conn->stats.open_files_count);
\twrite_unlock(&global_ft.lock);
"""
    new_rebind = """\twrite_lock(&global_ft.lock);
\tspin_lock(&fp->f_lock);
\told_conn = fp->conn;
\tfp->conn = ksmbd_conn_get(work->conn);
\tatomic_inc(&fp->conn->stats.open_files_count);
\tatomic_dec(&old_conn->stats.open_files_count);
\tspin_unlock(&fp->f_lock);
\twrite_unlock(&global_ft.lock);
"""
    text = replace_once(text, old_rebind, new_rebind, "ksmbd_rebind_replay_fd writer")
    return text


def main():
    if len(sys.argv) != 2 or sys.argv[1] not in ("instrument", "fix"):
        raise SystemExit("usage: prepare_ksmbd_race.py instrument|fix")
    text = PATH.read_text()
    if sys.argv[1] == "instrument":
        text = instrument(text)
    else:
        text = fix(text)
    PATH.write_text(text)
    print(f"Applied {sys.argv[1]} transformation to {PATH}")


if __name__ == "__main__":
    main()
