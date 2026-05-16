import ctypes
user32 = ctypes.windll.user32
kernel32 = ctypes.windll.kernel32

kernel32.GlobalAlloc.restype = ctypes.c_void_p
kernel32.GlobalAlloc.argtypes = [ctypes.c_uint, ctypes.c_size_t]
kernel32.GlobalLock.restype = ctypes.c_void_p
kernel32.GlobalLock.argtypes = [ctypes.c_void_p]
kernel32.GlobalUnlock.argtypes = [ctypes.c_void_p]
user32.SetClipboardData.restype = ctypes.c_void_p
user32.SetClipboardData.argtypes = [ctypes.c_uint, ctypes.c_void_p]

def secure_copy(text):
    CF_UNICODETEXT = 13
    fmt = user32.RegisterClipboardFormatW('ExcludeClipboardContentFromMonitorProcessing')
    user32.OpenClipboard(None)
    user32.EmptyClipboard()
    
    text_encoded = text.encode('utf-16le') + b'\0\0'
    hMem = kernel32.GlobalAlloc(0x0042, len(text_encoded))
    if hMem:
        pMem = kernel32.GlobalLock(hMem)
        ctypes.memmove(pMem, text_encoded, len(text_encoded))
        kernel32.GlobalUnlock(hMem)
        user32.SetClipboardData(CF_UNICODETEXT, hMem)
    
    hEx = kernel32.GlobalAlloc(0x0042, 1)
    if hEx:
        pEx = kernel32.GlobalLock(hEx)
        ctypes.memset(pEx, 0, 1)
        kernel32.GlobalUnlock(hEx)
        user32.SetClipboardData(fmt, hEx)
    
    user32.CloseClipboard()

secure_copy('SECRET_KEY_12345')
print('Done!')
