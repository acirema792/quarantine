"""requestz — thin wrapper so `import requestz` works."""
import urllib.request


def get(url, timeout=10):
    with urllib.request.urlopen(url, timeout=timeout) as resp:
        return resp.read()


__version__ = "2.32.4"
