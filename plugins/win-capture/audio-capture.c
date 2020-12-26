#include <obs-module.h>
#include <windows.h>
#include <ipc-util/pipe.h>
#include <util/dstr.h>
#include <util/platform.h>
#include <util/threading.h>

#include "obfuscate.h"
#include "inject-library.h"
#include "audio-helpers.h"
#include "audio-hook-info.h"

#define do_log(level, format, ...) blog(level, format, ##__VA_ARGS__)
#define warn(format, ...) do_log(LOG_WARNING, format, ##__VA_ARGS__)
#define info(format, ...) do_log(LOG_INFO, format, ##__VA_ARGS__)
#define debug(format, ...) do_log(LOG_DEBUG, format, ##__VA_ARGS__)

/*---------[SETTINGS]---------*/

#define SETTING_TARGET_PROCESS "target_process"
#define SETTING_INJECT_RATE "inject_rate"

/*----------[LABELS]----------*/

#define LABEL_AUDIO_CAPTURE obs_module_text("AudioCapture")

#define LABEL_TARGET_PROCESS obs_module_text("AudioCapture.TargetProcess")

#define LABEL_INJECT_RATE obs_module_text("AudioCapture.InjectRate")
#define LABEL_INJECT_RATE_SLOW obs_module_text("AudioCapture.InjectRate.Slow")
#define LABEL_INJECT_RATE_NORMAL \
	obs_module_text("AudioCapture.InjectRate.Normal")
#define LABEL_INJECT_RATE_FAST obs_module_text("AudioCapture.InjectRate.Fast")
#define LABEL_INJECT_RATE_FASTEST \
	obs_module_text("AudioCapture.InjectRate.Fastest")

/*-----------[MISC]-----------*/

#define BASE_INJECT_INTERVAL 0.5
#define INJECT_RATE_SLOW 8
#define INJECT_RATE_NORMAL 4
#define INJECT_RATE_FAST 2
#define INJECT_RATE_FASTEST 1

static inline void *os_atomic_set_ptr(volatile const void **ptr,
				      const void *val)
{
#ifdef _WIN64
	return (void *)_InterlockedExchange64((volatile LONG_PTR *)ptr,
					      (LONG_PTR)val);
#else
	return (void *)_InterlockedExchange((volatile long *)ptr, (long)val);
#endif
}

static inline void *os_atomic_load_ptr(volatile const void **ptr)
{
#ifdef _WIN64
	return (void *)_InterlockedOr64((volatile LONG_PTR *)ptr, 0LL);
#else
	return (void *)_InterlockedOr((volatile long *)ptr, 0LL);
#endif
}

struct audio_capture_data {
	obs_source_t *source;
	volatile long inject_rate;
	volatile const char *target_session_name;

	bool initialized_thread;
	pthread_t thread;
	os_event_t *event;

	HANDLE audio_procs_vec;
	HANDLE audio_pipes_list;
};

void pipe_read(void *param, uint8_t *buffer, size_t size)
{
	if (size < sizeof(struct audio_metadata))
		return;

	obs_source_t *source = (obs_source_t *)param;
	struct audio_metadata *md = (struct audio_metadata *)buffer;
	uint8_t *data = (uint8_t *)buffer + sizeof(struct audio_metadata);

	struct obs_source_audio audio;
	audio.format = md->format;
	audio.speakers = md->layout;
	audio.samples_per_sec = md->samples_per_sec;
	audio.timestamp = md->timestamp;
	audio.frames = md->frames;
	audio.data[0] = data;
	obs_source_output_audio(source, &audio);
}

static bool check_file_integrity(const char *file)
{
	DWORD error;
	HANDLE handle;
	wchar_t *w_file = NULL;

	if (!file || !*file) {
		warn("Audio capture %s not found.", file);
		return false;
	}

	if (!os_utf8_to_wcs_ptr(file, 0, &w_file)) {
		warn("Could not convert file name to wide string");
		return false;
	}

	handle = CreateFileW(w_file, GENERIC_READ | GENERIC_EXECUTE,
			     FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);

	bfree(w_file);

	if (handle != INVALID_HANDLE_VALUE) {
		CloseHandle(handle);
		return true;
	}

	error = GetLastError();
	if (error == ERROR_FILE_NOT_FOUND)
		warn("Audio capture file '%s' not found.", file);
	else if (error == ERROR_ACCESS_DENIED)
		warn("Audio capture file '%s' could not be loaded.", file);
	else
		warn("Audio capture file '%s' could not be loaded: %lu.", file,
		     error);

	return false;
}

static inline HMODULE kernel32(void)
{
	static HMODULE kernel32_handle = NULL;
	if (!kernel32_handle)
		kernel32_handle = GetModuleHandleW(L"kernel32");
	return kernel32_handle;
}

static inline HANDLE open_process(DWORD desired_access, bool inherit_handle,
				  DWORD process_id)
{
	typedef HANDLE(WINAPI * PFN_OpenProcess)(DWORD, BOOL, DWORD);
	PFN_OpenProcess open_process_proc =
		(PFN_OpenProcess)get_obfuscated_func(kernel32(), "NuagUykjcxr",
						     0x1B694B59451ULL);
	return open_process_proc(desired_access, inherit_handle, process_id);
}

static inline void close_handle(HANDLE *p_handle)
{
	if (*p_handle) {
		if (*p_handle != INVALID_HANDLE_VALUE)
			CloseHandle(*p_handle);
		*p_handle = NULL;
	}
}

static bool create_inject_helper_proc(DWORD pid, const char *inject_path,
				      const char *hook_dll)
{
	bool use_set_window_ex = false;

	wchar_t *command_line_w = bzalloc(4096 * sizeof(wchar_t));
	wchar_t *inject_path_w;
	wchar_t *hook_dll_w;

	PROCESS_INFORMATION pi = {0};
	STARTUPINFO si = {0};
	bool success = false;

	os_utf8_to_wcs_ptr(inject_path, 0, &inject_path_w);
	os_utf8_to_wcs_ptr(hook_dll, 0, &hook_dll_w);

	si.cb = sizeof(si);

	swprintf(command_line_w, 4096, L"\"%s\" \"%s\" %lu %lu", inject_path_w,
		 hook_dll_w, use_set_window_ex, pid);

	success = !!CreateProcessW(inject_path_w, command_line_w, NULL, NULL,
				   false, CREATE_NO_WINDOW, NULL, NULL, &si,
				   &pi);

	if (success) {
		CloseHandle(pi.hProcess);
		CloseHandle(pi.hThread);
	} else
		warn("Failed to create inject helper process: %lu",
		     GetLastError());

	bfree(command_line_w);
	bfree(inject_path_w);
	bfree(hook_dll_w);
	return success;
}

static void inject_hooks(struct audio_capture_data *acd)
{
	char *inject_path_32 = obs_module_file("inject-helper32.exe");
	char inject_path_32_full[MAX_PATH];
	_fullpath(inject_path_32_full, inject_path_32, MAX_PATH);
	char *hook_path_32 = obs_module_file("audio-hook32.dll");
	char hook_path_32_full[MAX_PATH];
	_fullpath(hook_path_32_full, hook_path_32, MAX_PATH);

	if (!check_file_integrity(inject_path_32_full) ||
	    !check_file_integrity(hook_path_32_full))
		goto cleanup_32;

#ifdef _WIN64
	char *inject_path_64 = obs_module_file("inject-helper64.exe");
	char inject_path_64_full[MAX_PATH];
	_fullpath(inject_path_64_full, inject_path_64, MAX_PATH);
	char *hook_path_64 = obs_module_file("audio-hook64.dll");
	char hook_path_64_full[MAX_PATH];
	_fullpath(hook_path_64_full, hook_path_64, MAX_PATH);

	if (!check_file_integrity(inject_path_64_full) ||
	    !check_file_integrity(hook_path_64_full))
		goto cleanup_all;
#endif

	struct audio_processes_info *procs = get_audio_procs_from_name(
		acd->audio_procs_vec,
		(const char *)os_atomic_load_ptr(&acd->target_session_name));
	if (procs)
		for (size_t i = 0; i < procs->count; i++) {
#ifdef _WIN64
			if (procs->x64_arr[i])
				create_inject_helper_proc(procs->pid_arr[i],
							  inject_path_64_full,
							  hook_path_64_full);
			else
#endif
				create_inject_helper_proc(procs->pid_arr[i],
							  inject_path_32_full,
							  hook_path_32_full);
		}

cleanup_all:
#ifdef _WIN64
	bfree(inject_path_64);
	bfree(hook_path_64);
#endif
cleanup_32:
	bfree(inject_path_32);
	bfree(hook_path_32);
}

static void insert_preserved_val(obs_property_t *p, const char *val, size_t idx)
{
	char listing_name[MAX_PATH];
	snprintf(listing_name, MAX_PATH, "[%s] Not currently open.", val);
	obs_property_list_insert_string(p, idx, listing_name, val);
	obs_property_list_item_disable(p, idx, true);
}

static bool check_window_property_setting(obs_properties_t *ppts,
					  obs_property_t *p,
					  obs_data_t *settings,
					  const char *setting_name, size_t idx)
{
	const char *cur_val;
	bool match = false;

	cur_val = obs_data_get_string(settings, setting_name);

	size_t count = obs_property_list_item_count(p);
	for (size_t i = 0; i < count; i++) {
		const char *val = obs_property_list_item_string(p, i);

		if (strcmp(val, cur_val) == 0) {
			match = true;
			break;
		}
	}

	if (cur_val && !match) {
		insert_preserved_val(p, cur_val, idx);
		return true;
	}

	UNUSED_PARAMETER(ppts);
	return false;
}

static bool fill_procs_property_list(struct audio_capture_data *acd,
				     obs_property_t *p)
{
	if (!refresh_audio_procs(acd->audio_procs_vec))
		return false;

	size_t count = get_audio_procs_count(acd->audio_procs_vec);
	for (size_t i = 0; i < count; i++) {
		struct audio_processes_info *audio_procs =
			get_audio_procs(acd->audio_procs_vec, i);
		if (!audio_procs)
			continue;

		char listing_name[MAX_PATH];
		char display_name_mbs[MAX_PATH];
		os_wcs_to_mbs(audio_procs->display_name,
			      wcslen(audio_procs->display_name),
			      display_name_mbs, MAX_PATH);
		snprintf(listing_name, MAX_PATH, "[%s] %s",
			 audio_procs->session_name, display_name_mbs);

		obs_property_list_add_string(p, listing_name,
					     audio_procs->session_name);
	}
	return true;
}

static void *audio_capture_thread(void *data)
{
	struct audio_capture_data *acd = data;

	uint64_t last_time = os_gettime_ns();

	while (os_event_try(acd->event) == EAGAIN) {
		uint64_t inject_interval = (uint64_t)(
			BASE_INJECT_INTERVAL *
			os_atomic_load_long(&acd->inject_rate) * 1e9);

		if (os_gettime_ns() - last_time > inject_interval) {
			last_time = os_gettime_ns();
			const char *session_name =
				os_atomic_load_ptr(&acd->target_session_name);
			refresh_audio_pipes(acd->audio_procs_vec,
					    acd->audio_pipes_list, session_name,
					    pipe_read, acd->source);
			inject_hooks(acd);
		}
	}
	UNUSED_PARAMETER(data);
	return NULL;
}

/*----[AUDIO CAPTURE INFO]----*/

static const char *audio_capture_name(void *unused)
{
	UNUSED_PARAMETER(unused);
	return LABEL_AUDIO_CAPTURE;
}

static void audio_capture_destroy(void *data)
{
	struct audio_capture_data *acd = data;
	if (acd) {
		if (acd->initialized_thread) {
			os_event_signal(acd->event);
			pthread_join(acd->thread, NULL);
		}
		os_event_destroy(acd->event);
		free_audio_procs_vec(acd->audio_procs_vec);
		free_audio_pipes_list(acd->audio_pipes_list);
		bfree(acd);
	}
}

static void audio_capture_defaults(obs_data_t *settings)
{
	obs_data_set_default_int(settings, SETTING_INJECT_RATE,
				 INJECT_RATE_NORMAL);
	obs_data_set_default_string(settings, SETTING_TARGET_PROCESS, "");
	UNUSED_PARAMETER(settings);
}

static void *audio_capture_create(obs_data_t *settings, obs_source_t *source)
{
	struct audio_capture_data *acd =
		bzalloc(sizeof(struct audio_capture_data));

	acd->source = source;
	acd->audio_procs_vec = create_audio_procs_vec();
	acd->audio_pipes_list = create_audio_pipes_list();

	os_atomic_set_long(&acd->inject_rate,
			   (long)obs_data_get_int(settings,
						  SETTING_INJECT_RATE));
	os_atomic_set_ptr(&acd->target_session_name,
			  obs_data_get_string(settings,
					      SETTING_TARGET_PROCESS));

	if (os_event_init(&acd->event, OS_EVENT_TYPE_MANUAL) != 0)
		goto fail;
	if (pthread_create(&acd->thread, NULL, audio_capture_thread, acd) != 0)
		goto fail;

	acd->initialized_thread = true;

	UNUSED_PARAMETER(settings);
	return acd;

fail:
	audio_capture_destroy(acd);
	return NULL;
}

static void audio_capture_update(void *data, obs_data_t *settings)
{
	struct audio_capture_data *acd = data;
	const char *new_session_name =
		obs_data_get_string(settings, SETTING_TARGET_PROCESS);
	os_atomic_set_ptr(&acd->target_session_name, new_session_name);
	os_atomic_set_long(&acd->inject_rate,
			   (long)obs_data_get_int(settings,
						  SETTING_INJECT_RATE));

	refresh_audio_pipes(acd->audio_procs_vec, acd->audio_pipes_list,
			    new_session_name, pipe_read, acd->source);
}

/*--------[PROPERTIES]--------*/

static bool target_name_callback(obs_properties_t *ppts, obs_property_t *p,
				 obs_data_t *settings)
{
	return check_window_property_setting(ppts, p, settings,
					     SETTING_TARGET_PROCESS, 1);
}

static obs_properties_t *audio_capture_properties(void *data)
{
	struct audio_capture_data *acd = data;
	obs_properties_t *ppts = obs_properties_create();
	obs_property_t *p;

	p = obs_properties_add_list(ppts, SETTING_TARGET_PROCESS,
				    LABEL_TARGET_PROCESS, OBS_COMBO_TYPE_LIST,
				    OBS_COMBO_FORMAT_STRING);
	obs_property_list_add_string(p, "", "");
	fill_procs_property_list(acd, p);
	obs_property_set_modified_callback(p, target_name_callback);

	p = obs_properties_add_list(ppts, SETTING_INJECT_RATE,
				    LABEL_INJECT_RATE, OBS_COMBO_TYPE_LIST,
				    OBS_COMBO_FORMAT_INT);
	obs_property_list_add_int(p, LABEL_INJECT_RATE_SLOW, INJECT_RATE_SLOW);
	obs_property_list_add_int(p, LABEL_INJECT_RATE_NORMAL,
				  INJECT_RATE_NORMAL);
	obs_property_list_add_int(p, LABEL_INJECT_RATE_FAST, INJECT_RATE_FAST);
	obs_property_list_add_int(p, LABEL_INJECT_RATE_FASTEST,
				  INJECT_RATE_FASTEST);

	return ppts;
}

struct obs_source_info audio_capture_info = {
	.id = "audio_capture",
	.type = OBS_SOURCE_TYPE_INPUT,
	.output_flags = OBS_SOURCE_AUDIO,
	.get_name = audio_capture_name,
	.create = audio_capture_create,
	.destroy = audio_capture_destroy,
	.update = audio_capture_update,
	.get_defaults = audio_capture_defaults,
	.get_properties = audio_capture_properties,
	.icon_type = OBS_ICON_TYPE_AUDIO_OUTPUT};
