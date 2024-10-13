# dtc but works
import ctypes
import random
import string
import time
import threading
import os
import win32api
import win32con
import win32gui
import win32process
import win32security
from ctypes import wintypes

try:
    ctypes.windll.user32.ShowWindow(ctypes.windll.kernel32.GetConsoleWindow(), 0)
except:
    pass

try:
    snapshot = ctypes.windll.kernel32.CreateToolhelp32Snapshot(0x00000002, 0)
    entry = ctypes.create_string_buffer(568)
    entry.dwSize = 568
    process_id = None

    if ctypes.windll.kernel32.Process32First(snapshot, ctypes.byref(entry)):
        while ctypes.windll.kernel32.Process32Next(snapshot, ctypes.byref(entry)):
            if entry.szExeFile.decode() == "RobloxPlayerBeta.exe":
                process_id = entry.th32ProcessID
                break

    ctypes.windll.kernel32.CloseHandle(snapshot)
    if process_id is None:
        print("[ERROR] Roblox process not found.")
        exit(1)
except:
    print("[ERROR] Failed to get process ID.")

try:
    def get_random_string(length):
        characters = string.ascii_letters + string.digits
        return ''.join(random.choice(characters) for _ in range(length))

    def change_console_title():
        while True:
            ctypes.windll.kernel32.SetConsoleTitleW(get_random_string(16))
            time.sleep(0.1)

    threading.Thread(target=change_console_title, daemon=True).start()
except:
    print("[ERROR] Failed to start the title thread.")

try:
    print("[INFO] Waiting for Roblox process...")

    while True:
        window_handle = win32gui.FindWindow(None, "Roblox")
        if win32gui.IsWindowVisible(window_handle):
            break
        time.sleep(0.1)

    os.system('cls')

    def check_roblox_window():
        while True:
            if not win32gui.FindWindow(None, "Roblox"):
                os._exit(0)
            time.sleep(0.1)

    threading.Thread(target=check_roblox_window, daemon=True).start()
except:
    print("[ERROR] Failed to monitor the Roblox window.")

try:
    process_handle = ctypes.windll.kernel32.OpenProcess(win32con.PROCESS_ALL_ACCESS, False, process_id)

    wintrust_module = ctypes.windll.kernel32.LoadLibraryA(b"wintrust.dll")
    win_verify_trust = ctypes.windll.kernel32.GetProcAddress(wintrust_module, b"WinVerifyTrust")

    payload = b"\x48\x31\xC0\x59\xFF\xE1" # thanks to ballistic src for payload!! check them out: github.com/0Zayn/Ballistic

    old_protect = ctypes.c_ulong(0)
    if not ctypes.windll.kernel32.VirtualProtectEx(process_handle, win_verify_trust, len(payload), win32con.PAGE_EXECUTE_READWRITE, ctypes.byref(old_protect)):
        print("[ERROR] Failed to protect WinVerifyTrust.")

    bytes_written = ctypes.c_size_t(0)
    if not ctypes.windll.kernel32.WriteProcessMemory(process_handle, win_verify_trust, payload, len(payload), ctypes.byref(bytes_written)):
        print("[ERROR] Failed to patch WinVerifyTrust.")

    if not ctypes.windll.kernel32.VirtualProtectEx(process_handle, win_verify_trust, len(payload), win32con.PAGE_EXECUTE_READ, ctypes.byref(old_protect)):
        print("[ERROR] Failed to restore protection on WinVerifyTrust.")
except:
    print("[ERROR] Failed to patch WinVerifyTrust.")

try:
    thread_id = win32process.GetWindowThreadProcessId(window_handle)[0]

    target_module = ctypes.windll.kernel32.LoadLibraryExA(b"SomethingModule.dll", None, win32con.DONT_RESOLVE_DLL_REFERENCES)
    dll_export = ctypes.windll.kernel32.GetProcAddress(target_module, b"NextHook")

    handle = ctypes.windll.user32.SetWindowsHookExA(win32con.WH_GETMESSAGE, dll_export, target_module, thread_id)
    if not handle:
        print("[ERROR] Module hook failed.")

    if not ctypes.windll.user32.PostThreadMessageA(thread_id, win32con.WM_NULL, 0, 0):
        print("[ERROR] Failed to post thread message.")
except:
    print("[ERROR] Failed to attach module hook.")

try:
    print("[SUCCESS] Module attached successfully.")
    while True:
        time.sleep(1)
except:
    print("[ERROR] An error occurred during the execution.")
