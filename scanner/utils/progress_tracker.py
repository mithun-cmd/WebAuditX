scan_tasks = {}

def init_scan(scan_id, target):
    scan_tasks[scan_id] = {
        "target": target,
        "progress": 0,
        "status": "starting",
        "message": "Starting scan...",
        "result": None,
        "logs": []
    }

def update_progress(scan_id, progress=None, status=None, message=None):
    if scan_id in scan_tasks:
        if progress is not None:
            scan_tasks[scan_id]["progress"] = progress
        if status:
            scan_tasks[scan_id]["status"] = status
        if message:
            scan_tasks[scan_id]["message"] = message

# 🔥 IMPROVED LOG SYSTEM
def add_log(scan_id, message):
    if scan_id in scan_tasks:
        from datetime import datetime

        timestamp = datetime.now().strftime("%H:%M:%S")
        log_entry = f"[{timestamp}] {message}"

        scan_tasks[scan_id]["logs"].append(log_entry)

        # ✅ limit logs (avoid memory issues)
        scan_tasks[scan_id]["logs"] = scan_tasks[scan_id]["logs"][-200:]


def complete_scan(scan_id, result):
    if scan_id in scan_tasks:
        scan_tasks[scan_id]["status"] = "completed"
        scan_tasks[scan_id]["progress"] = 100
        scan_tasks[scan_id]["result"] = result


def get_progress(scan_id):
    return scan_tasks.get(scan_id, {})