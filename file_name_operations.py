
def remove_continuous_slashes(path: str) -> str:
    while True:
        l = len(path)
        path = path.replace('//', '/')
        if len(path) == l:
            return path


def name_legal(name: str) -> bool:
    if (len(name) == 0 or len(name) > 255):
        return False
    if (name == '.' or name == '..'):
        return False
    if ('/' in name):
        return False
    return True


def resolve_path(path: str) -> str:
    path = remove_continuous_slashes(path)
    if (path[-1] == '/'):
        path = path[:-1]
    path_elements = path.split('/')[1:]
    elemnets = []
    for pe in path_elements:
        if pe == '.':
            continue
        if pe == '..':
            if len(elemnets) > 0:
                elemnets.pop()
            continue
        elemnets.append(pe)
    final_path = '/'
    for e in elemnets:
        final_path += e + '/'
    return final_path[:-1] if final_path != '/' else '/'

def path_elements(path: str) -> list[str]:
    path = remove_continuous_slashes(path)
    if (path[-1] == '/'):
        path = path[:-1]
    path_elements = path.split('/')[1:]
    elemnets = []
    for pe in path_elements:
        if pe == '.':
            continue
        if pe == '..':
            if len(elemnets) > 0:
                elemnets.pop()
            continue
        elemnets.append(pe)
    return elemnets


def src_in_dest(src: str, dest: str) -> bool:
    src = remove_continuous_slashes(src)
    dest = remove_continuous_slashes(dest)
    src_elements = path_elements(src)
    dest_elements = path_elements(dest)
    if len(src_elements) > len(dest_elements):
        return False
    for i in range(len(src_elements)):
        if src_elements[i] != dest_elements[i]:
            return False
    return True
