import threading
import uuid

tasks = {}

def create_task(target):
    task_id = str(uuid.uuid4())

    tasks[task_id] = {
        "status": "running",
        "progress": 0,
        "result": None,
        "target": target
    }

    return task_id

def update_task(task_id, progress=None, status=None, result=None):
    if task_id in tasks:
        if progress is not None:
            tasks[task_id]["progress"] = progress
        if status:
            tasks[task_id]["status"] = status
        if result:
            tasks[task_id]["result"] = result

def get_task(task_id):
    return tasks.get(task_id)