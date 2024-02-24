import win32process, win32api, psutil

PROCESS_ALL_ACCESS = 0x1F0FFF

handle = None

def get_base_address(handle):
    modules = win32process.EnumProcessModules(handle)
    return modules[0]

def get_pids(process_name):
    pids = [p.pid for p in psutil.process_iter() if p.name() == process_name]
    return pids

def memory_compare(data, sig, mask):
    for i in range(len(sig)):
        if mask[i] == 'x':
            try:
                if data[i] != sig[i]:
                    return False
            except IndexError:
                return False
    return True

def find_signature(handle, start, size, sig, mask):
    while True:
        bytes = win32process.ReadProcessMemory(handle, start, size)

        for i in range(len(bytes)):
            if memory_compare(bytes[i:i+len(sig)], sig, mask):
                return start + i

        start += len(bytes)

def get_authentication_check_func_offset():
    base_address = get_base_address(handle)

    offset = find_signature(handle, base_address, 0x7FFF, b'\x55\x41\x57\x41\x56\x41\x55\x41\x54\x56\x57\x53\x48\x81\xEC\x00\x00\x00\x00\x48\x8D\xAC\x24\x00\x00\x00\x00\x48\xC7\x85\x00\x00\x00\x00\x00\x00\x00\x00\x4D\x89\xCC\x4C\x89\x85\x00\x00\x00\x00', 'xxxxxxxxxxxxxxx????xxxx????xxx????????xxxxxx????')

    return offset

pid = get_pids('sublime_text.exe')[0]
handle = win32api.OpenProcess(PROCESS_ALL_ACCESS, False, pid)

authentication_check_func_offset = get_authentication_check_func_offset()

win32process.WriteProcessMemory(handle, authentication_check_func_offset, b'\xB8\x00\x00\x00\x00\xC3\x90')
print('Unlocked Sublime Text!')
