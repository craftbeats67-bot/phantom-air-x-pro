import logging, os
from core import config
_log = None
def get():
    global _log
    if _log is None:
        os.makedirs(config.LOGS, exist_ok=True)
        _log = logging.getLogger("phantom")
        _log.setLevel(logging.INFO)
        if not _log.handlers:
            h = logging.FileHandler(os.path.join(config.LOGS, "phantom.log"))
            h.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
            _log.addHandler(h)
    return _log
