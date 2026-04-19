scan_progress = {}

def init_scan(scan_id):
    scan_progress[scan_id] = {
        "progress": 0,
        "status": "Starting..."
    }

def update_progress(scan_id, progress, status):
    scan_progress[scan_id]["progress"] = progress
    scan_progress[scan_id]["status"] = status

def get_progress(scan_id):
    return scan_progress.get(scan_id, {})