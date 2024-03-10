try:
    from block import gen_tar_gz, upload_tar_gz
except:
    from .block import gen_tar_gz, upload_tar_gz
from threading import Lock
from typing import Callable, Tuple
from _thread import start_new_thread


class Uploader:
    def __init__(self, thread_num: int,
                 on_fail: Callable[[str, str, int], Tuple[str, str]],
                 on_success: Callable[[str], None]):
        '''
        on_fail: 输入 (project_name, pypi_token, reason), 输出 (project_name, pypi_token)
        '''
        self.task_num = 0
        self.thread_num = thread_num
        self.task_status = {}
        self.lock = Lock()
        self.on_fail = on_fail
        self.on_success = on_success

    def is_finished(self) -> bool:
        with self.lock:
            return self.task_num == 0

    def is_available(self) -> bool:
        with self.lock:
            return self.task_num < self.thread_num

    def add_task(self, name: str, data: bytes, pypi_token: str):
        with self.lock:
            self.task_num += 1
            self.task_status[name] = 0
        start_new_thread(self.upload_thread, (name, data, pypi_token))

    def upload_thread(self, name: str, data: bytes, pypi_token: str):
        status = upload_tar_gz(name, data, pypi_token)
        if (status == 3):
            # 未知错误, 再重试一次
            status = self.upload_till_success(name, data, pypi_token)
        if (status == -3):
            print("Network error!")
            return
        if (status == -2 or status == 2):
            new_name, new_token = self.on_fail(name, pypi_token, status)
            return self.upload_thread(new_name, data, new_token)
        if (status == -1):
            print("Pypi token incorrect!")
            return
        with self.lock:
            self.task_num -= 1
            self.task_status[name] = 1
        self.on_success(name)

    def upload_till_success(self, name: str, data: bytes, pypi_token: str):
        status = -3
        cnt = 5
        while (status == -3 and cnt > 0):
            cnt -= 1
            status = upload_tar_gz(name, data, pypi_token)
        return status
