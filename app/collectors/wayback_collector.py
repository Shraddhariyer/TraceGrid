import requests
import time


def get_wayback_data(domain: str):
    url = f"https://web.archive.org/cdx/search/cdx?url={domain}&output=json"

    headers = {
        "User-Agent": "Mozilla/5.0"
    }

    for attempt in range(2):  # retry once
        try:
            response = requests.get(url, headers=headers, timeout=15)

            # ❌ If blocked or failed
            if response.status_code != 200:
                return {
                    "status": "failed",
                    "snapshot_count": None,
                    "first_seen": None,
                    "last_seen": None
                }

            data = response.json()

            # ❌ No snapshots but API worked
            if len(data) <= 1:
                return {
                    "status": "ok",
                    "snapshot_count": 0,
                    "first_seen": None,
                    "last_seen": None
                }

            snapshots = data[1:]

            count = len(snapshots)

            # Wayback format: [urlkey, timestamp, original...]
            first_seen = snapshots[0][1][:8] if len(snapshots[0]) > 1 else None
            last_seen = snapshots[-1][1][:8] if len(snapshots[-1]) > 1 else None

            return {
                "status": "ok",
                "snapshot_count": count,
                "first_seen": first_seen,
                "last_seen": last_seen
            }

        except Exception as e:
            print(f"[INFO] Wayback attempt {attempt+1} failed:", e)
            time.sleep(2)

    # ❌ If all attempts fail → API unreliable
    return {
        "status": "failed",
        "snapshot_count": None,
        "first_seen": None,
        "last_seen": None
    }