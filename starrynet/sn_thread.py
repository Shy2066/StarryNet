"""Worker error propagation that also works before threading.excepthook (3.8)."""
import threading

WORKER_ERRORS = []


class CheckedThread(threading.Thread):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.worker_error = None
        original_run = self.run
        # Small worker implementations may provide run_checked instead of
        # overriding run; preserve that convention for legacy subclasses.
        if (getattr(original_run, '__func__', None) is threading.Thread.run and
                callable(getattr(self, 'run_checked', None))):
            original_run = self.run_checked

        def checked_run():
            try:
                original_run()
            except BaseException as exc:
                self.worker_error = exc
                WORKER_ERRORS.append(str(exc))

        self.run = checked_run

    def run_checked(self):
        """Execute the subclass's worker body directly in offline checks."""
        implementation = getattr(type(self), 'run', threading.Thread.run)
        if implementation is CheckedThread.run:
            return threading.Thread.run(self)
        return implementation(self)

    def join(self, timeout=None):
        super().join(timeout)
        if not self.is_alive() and self.worker_error is not None:
            raise RuntimeError('Background StarryNet worker failed') from self.worker_error
