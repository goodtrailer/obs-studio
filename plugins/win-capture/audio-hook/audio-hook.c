#include <Windows.h>
#include <stdbool.h>
#include <stdio.h>
#include "core-audio-capture.h"
#include "../obfuscate.h"
#include "../hook-helpers.h"

#define DEBUG_OUTPUT

#ifdef DEBUG_OUTPUT
#define DbgOut(x) OutputDebugStringA(x)
#else
#define DbgOut(x)
#endif

#define HOOK_NAME L"audio_hook_dup_mutex"

static HANDLE g_dup_mutex = NULL;

static inline HANDLE open_mutex_plus_id(const wchar_t *name, DWORD id)
{
	wchar_t new_name[64];
	_snwprintf(new_name, 64, L"%s%lu", name, id);
	return open_mutex(new_name);
}

static inline void close_handle(HANDLE *handle)
{
	if (*handle && *handle != INVALID_HANDLE_VALUE)
		CloseHandle(*handle);
	*handle = NULL;
}

static bool init_dll(void)
{
	DWORD PID = GetCurrentProcessId();
	HANDLE h;

	h = open_mutex_plus_id(HOOK_NAME, PID);
	if (h) {
		CloseHandle(h);
		return false;
	}

	g_dup_mutex = create_mutex_plus_id(HOOK_NAME, PID);
	return !!g_dup_mutex;
}

BOOL WINAPI DllMain(HINSTANCE hinst, DWORD reason, LPVOID reserved)
{
	if (reason == DLL_PROCESS_ATTACH) {
		if (!init_dll())
			return false;
		hook_core_audio();
	} else if (reason == DLL_PROCESS_DETACH) {
		if (!g_dup_mutex)
			return true;
		close_handle(&g_dup_mutex);
		unhook_core_audio();
	}

	(void)reserved;
	(void)hinst;
	return true;
}

// for future setwindowshookex stuff thats not implemented yet
__declspec(dllexport) LRESULT CALLBACK
	dummy_debug_proc(int code, WPARAM wparam, LPARAM lparam)
{
	static bool hooking = true;
	MSG *msg = (MSG *)lparam;

	if (hooking && msg->message == (WM_USER + 432)) {
		HMODULE user32 = GetModuleHandleW(L"USER32");
		typedef BOOL(WINAPI * unhook_windows_hook_ex_t)(HHOOK);
		unhook_windows_hook_ex_t unhook_windows_hook_ex = NULL;

		unhook_windows_hook_ex =
			(unhook_windows_hook_ex_t)get_obfuscated_func(
				user32, "VojeleY`bdgxvM`hhDz",
				0x7F55F80C9EE3A213ULL);

		if (unhook_windows_hook_ex)
			unhook_windows_hook_ex((HHOOK)msg->lParam);
		hooking = false;
	}
	return CallNextHookEx(NULL, code, wparam, lparam);
}
