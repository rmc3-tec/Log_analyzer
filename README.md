# Log_analyzer
A Python tool that reads authentication logs, counts successful and failed logins, and flags suspicious activity such as brute-force and password-guessing attempts. It writes a plain-text security report where every alert explains why it was flagged.

from datetime import datetime, timedelta
from collections import defaultdict

log_file = "auth.log"
report_file = "Security_Report.txt"
failure_threshold = 3
time_window = timedelta(minutes=5)
TS = "%Y-%m-%d %H:%M:%S"

total_success = 0
total_failed = 0
events_by_ip = defaultdict(list)    # ip -> [(time, username)]
events_by_user = defaultdict(list)  # username -> [(time, ip)]

with open(log_file, "r") as file: #opens the file 
    for line in file:
        line = line.strip()
        if line == "":
            continue

        parts = [p.strip() for p in line.split(",")] #parsing the individual logs 
        if len(parts) != 4:
            print("Skipping invalid log entry:", line)
            continue

        timestamp, status, ip_address, username = parts # the 5 parts that are being parsed 

        try:
            event_time = datetime.strptime(timestamp, TS)
        except ValueError:
            print("Skipping entry with bad timestamp:", line)
            continue

        if status == "SUCCESS":     #categorizing if it attempt succedded or failed
            total_success += 1
        elif status == "FAILED":
            total_failed += 1
            events_by_ip[ip_address].append((event_time, username))
            events_by_user[username].append((event_time, ip_address))
        else:
            print("Unknown login status:", status)

ip_alerts = []
user_alerts = []
window_alerts = []
def densest_window(events, window, threshold):
    """Return (start_idx, end_idx, size) of the densest qualifying window, or None."""
    best = None
    left = 0
    for right, (t, _) in enumerate(events):
        while t - events[left][0] > window:
            left += 1
        size = right - left + 1
        if size >= threshold and (best is None or size > best[2]):
            best = (left, right, size)
    return best


def build_window_alert(ip, events, best):
    start_idx, end_idx, size = best
    window_events = events[start_idx:end_idx + 1]
    return {
        "ip": ip,
        "count": size,
        "start": window_events[0][0],
        "end": window_events[-1][0],
        "times": [t for t, _ in window_events],
        "usernames": sorted({u for _, u in window_events}),
    }
# Rule 1: failures from one IP
for ip, events in events_by_ip.items():
    if len(events) >= failure_threshold:
        events.sort()
        ip_alerts.append({
            "ip": ip,
            "count": len(events),
            "first": events[0][0],
            "last": events[-1][0],
            "usernames": sorted({u for _, u in events}),
        })

# Rule 2: failures against one username
for user, events in events_by_user.items():
    if len(events) >= failure_threshold:
        events.sort()
        user_alerts.append({
            "username": user,
            "count": len(events),
            "first": events[0][0],
            "last": events[-1][0],
            "ips": sorted({ip for _, ip in events}),
        })

# Rule 3: burst of failures from one IP inside the time window
for ip, events in events_by_ip.items():
    events.sort()
    best = densest_window(events, time_window, failure_threshold)
    if best:
        window_alerts.append(build_window_alert(ip, events, best))

# ---------- Report ----------
minutes = int(time_window.total_seconds() // 60)
with open(report_file, "w") as file:
    file.write("===== SECURITY LOG REPORT =====\n")
    file.write(f"Successful logins: {total_success}\n")
    file.write(f"Failed logins: {total_failed}\n")

    file.write("\nFailed Attempts by IP:\n")
    for ip, events in events_by_ip.items():
        file.write(f"{ip}: {len(events)} failed attempts\n")

    file.write("\nFailed Attempts by Username:\n")
    for user, events in events_by_user.items():
        file.write(f"{user}: {len(events)} failed attempts\n")

    file.write("\n===== ALERT: REPEATED FAILURES BY IP =====\n")
    if ip_alerts:
        for a in ip_alerts:
            file.write(f"\n[ALERT] IP {a['ip']}\n")
            file.write(f"  Why flagged: {a['count']} failed logins from this IP "
                       f"(threshold is {failure_threshold})\n")
            file.write(f"  First failure: {a['first'].strftime(TS)}\n")
            file.write(f"  Last failure:  {a['last'].strftime(TS)}\n")
            file.write(f"  Usernames targeted: {', '.join(a['usernames'])}\n")
    else:
        file.write("No IP exceeded the failure threshold.\n")

    file.write("\n===== ALERT: REPEATED FAILURES BY USERNAME =====\n")
    if user_alerts:
        for a in user_alerts:
            file.write(f"\n[ALERT] Username '{a['username']}'\n")
            file.write(f"  Why flagged: {a['count']} failed logins against this account "
                       f"(threshold is {failure_threshold})\n")
            file.write(f"  First failure: {a['first'].strftime(TS)}\n")
            file.write(f"  Last failure:  {a['last'].strftime(TS)}\n")
            file.write(f"  Source IPs: {', '.join(a['ips'])}\n")
    else:
        file.write("No username exceeded the failure threshold.\n")

    file.write("\n===== ALERT: RAPID FAILURES (TIME-BASED) =====\n")
    if window_alerts:
        for a in window_alerts:
            file.write(f"\n[ALERT] IP {a['ip']}\n")
            file.write(f"  Why flagged: {a['count']} failed logins within {minutes} minutes "
                       f"(threshold is {failure_threshold})\n")
            file.write(f"  Window: {a['start'].strftime(TS)} to {a['end'].strftime(TS)}\n")
            file.write("  Failure times: "
                       + ", ".join(t.strftime("%H:%M:%S") for t in a["times"]) + "\n")
            file.write(f"  Usernames tried: {', '.join(a['usernames'])}\n")
    else:
        file.write(f"No IP had {failure_threshold} failed logins within {minutes} minutes.\n")

print(f"File saved to {report_file}")
