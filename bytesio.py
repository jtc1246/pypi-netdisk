import io
import os
import builtins


class BytesioData:
    def __init__(self):
        self.data = {}

    def register(self, name: str, content: bytes):
        self.data[name] = content

    def get(self, name: str):
        return self.data.get(name, None)

    def get_len(self, name: str):
        content = self.data.get(name, None)
        # return len(content) if content is not None else 0
        if content is not None:
            return len(content)
        raise FileNotFoundError(f"No data registered under name: {name}")

    def free(self, name: str):
        if name in self.data:
            del self.data[name]


bd = BytesioData()


# Save the original functions
origin_open = builtins.open
origin_exists = os.path.exists
origin_getsize = os.path.getsize


def my_open(path, *args, **kwargs):
    if path.startswith('/bytes-jtc/'):
        name = path.split('/')[-1]
        data = bd.get(name)
        if data is not None:
            return io.BytesIO(data)
        # Fallback to raising an error if data does not exist
        raise FileNotFoundError(f"No data registered under name: {name}")
    else:
        # Call the original open for non-matching paths
        return origin_open(path, *args, **kwargs)


def my_exists(path, *args, **kwargs):
    if path.startswith('/bytes-jtc/'):
        name = path.split('/')[-1]
        return name in bd.data
    else:
        return origin_exists(path, *args, **kwargs)


def my_getsize(path, *args, **kwargs):
    if path.startswith('/bytes-jtc/'):
        name = path.split('/')[-1]
        return bd.get_len(name)
    else:
        return origin_getsize(path, *args, **kwargs)


# Apply the monkey-patching
builtins.open = my_open
os.path.exists = my_exists
os.path.getsize = my_getsize
