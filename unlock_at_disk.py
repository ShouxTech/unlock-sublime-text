FILE_PATH = 'C:\Program Files\Sublime Text\sublime_text.exe'

def memory_compare(data, sig, mask):
    for i in range(len(sig)):
        if mask[i] == 'x':
            try:
                if data[i] != sig[i]:
                    return False
            except IndexError:
                return False
    return True

def find_signature(file_path, sig, mask):
    with open(file_path, 'rb') as f:
        data = f.read()
        file_size = len(data)

        for i in range(file_size):
            if memory_compare(data[i:i+len(sig)], sig, mask):
                return i

    return -1

def modify_file(file_path, offset, new_data):
    with open(file_path, 'r+b') as f:
        f.seek(offset)
        f.write(new_data)

def get_authentication_check_func_offset(file_path):
    offset = find_signature(file_path, b'\x55\x41\x57\x41\x56\x41\x55\x41\x54\x56\x57\x53\x48\x81\xEC\x00\x00\x00\x00\x48\x8D\xAC\x24\x00\x00\x00\x00\x48\xC7\x85\x00\x00\x00\x00\x00\x00\x00\x00\x4D\x89\xCC\x4C\x89\x85\x00\x00\x00\x00', 'xxxxxxxxxxxxxxx????xxxx????xxx????????xxxxxx????')
    return offset

authentication_check_func_offset = get_authentication_check_func_offset(FILE_PATH)

if authentication_check_func_offset != -1:
    modify_file(FILE_PATH, authentication_check_func_offset, b'\xB8\x00\x00\x00\x00\xC3\x90')
    print('Unlocked Sublime Text!')
else:
    print('Signature not found in the file.')
