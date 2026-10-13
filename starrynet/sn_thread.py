"""Worker error propagation that also works before threading.excepthook (3.8)."""
import threading

WORKER_ERRORS = []


class CheckedThread(threading.Thread):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.worker_error = None
        original_run = self.run

        def checked_run():
            try:
                original_run()
            except BaseException as exc:
                self.worker_error = exc
                WORKER_ERRORS.append(str(exc))

        self.run = checked_run

    def join(self, timeout=None):
        super().join(timeout)
        if not self.is_alive() and self.worker_error is not None:
            raise self.worker_error
