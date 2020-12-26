#include "audio-helpers.h"

#include <Windows.h>
#include <audioclient.h>
#include <audiopolicy.h>
#include <mmeapi.h>
#include <mmdeviceapi.h>
#include <Psapi.h>
#include <vector>
#include <list>
#include <pthread.h>

template<typename T> static inline void safe_release(T **out_COM_obj)
{
	static_assert(std::is_base_of<IUnknown, T>::value,
		      "Object must implement IUnknown");
	if (*out_COM_obj)
		(*out_COM_obj)->Release();
	*out_COM_obj = nullptr;
}

/*--------[AUDIO PROC]--------*/

HANDLE create_audio_procs_vec()
{
	return new std::vector<audio_processes_info>;
}

bool refresh_audio_procs(HANDLE audio_procs_vec)
{
	std::vector<audio_processes_info> *vec =
		(std::vector<audio_processes_info> *)audio_procs_vec;

	if (!SUCCEEDED(CoInitialize(NULL)))
		return false;

	bool success = false;
	IMMDeviceEnumerator *device_enum = nullptr;
	IMMDevice *device = nullptr;
	IAudioSessionManager2 *session_manager;
	IAudioSessionEnumerator *session_enum;

	if (!SUCCEEDED(CoCreateInstance(
		    __uuidof(MMDeviceEnumerator), nullptr, CLSCTX_ALL,
		    __uuidof(IMMDeviceEnumerator), (void **)&device_enum)))
		goto out_uninitialize;

	if (!SUCCEEDED(device_enum->GetDefaultAudioEndpoint(
		    eRender, eMultimedia, &device)))
		goto out_release_device_enum;

	if (!SUCCEEDED(device->Activate(__uuidof(IAudioSessionManager2), 0,
					nullptr, (void **)&session_manager)))
		goto out_release_device;

	if (!SUCCEEDED(session_manager->GetSessionEnumerator(&session_enum)))
		goto out_release_session_manager;

	int session_count;
	session_enum->GetCount(&session_count);
	clear_audio_procs_vec(vec);
	vec->reserve(session_count);
	IAudioSessionControl *session_control = nullptr;
	IAudioSessionControl2 *session_control2 = nullptr;
	for (int i = 0; i < session_count; i++) {
		if (!SUCCEEDED(session_enum->GetSession(i, &session_control)))
			continue;

		if (!SUCCEEDED(session_control->QueryInterface(
			    &session_control2))) {
			safe_release(&session_control);
			continue;
		}
		DWORD pid;
		session_control2->GetProcessId(&pid);
		void *h_process = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);

		wchar_t *display_name;
		session_control->GetDisplayName(&display_name);
		char session_name[MAX_PATH];
		if (GetModuleBaseNameA(h_process, NULL, session_name,
				       MAX_PATH) != 0) {
			bool found_match = false;
			for (auto &procs : *vec) {
				if (strcmp(procs.session_name, session_name) ==
				    0) {
					if (*procs.display_name == L'\000')
						procs.display_name =
							display_name;
					BOOL x32 = true;
#ifdef _WIN64
					IsWow64Process(h_process, &x32);
#endif
					add_pid_to_audio_procs(&procs, pid,
							       !x32);
					found_match = true;
					break;
				}
			}
			if (!found_match) {
				auto &procs = vec->emplace_back();
				procs.display_name = display_name;
				strcpy(procs.session_name, session_name);
				procs.display_name = display_name;
				BOOL x32 = true;
#ifdef _WIN64
				IsWow64Process(h_process, &x32);
#endif
				procs.pid_arr = NULL;
				procs.x64_arr = NULL;
				add_pid_to_audio_procs(&procs, pid, !x32);
			}
		}

		CloseHandle(h_process);
		safe_release(&session_control2);
		safe_release(&session_control);
	}
	success = true;

	safe_release(&session_enum);
out_release_session_manager:
	safe_release(&session_manager);
out_release_device:
	safe_release(&device);
out_release_device_enum:
	safe_release(&device_enum);
out_uninitialize:
	CoUninitialize();
	return success;
}

size_t get_audio_procs_count(HANDLE audio_procs_vec)
{
	std::vector<audio_processes_info> *vec =
		(std::vector<audio_processes_info> *)audio_procs_vec;
	return vec->size();
}

audio_processes_info *get_audio_procs(HANDLE audio_procs_vec, size_t index)
{
	std::vector<audio_processes_info> *vec =
		(std::vector<audio_processes_info> *)audio_procs_vec;
	return &vec->at(index);
}

audio_processes_info *get_audio_procs_from_name(HANDLE audio_procs_vec,
						const char *const session_name)
{
	std::vector<audio_processes_info> *vec =
		(std::vector<audio_processes_info> *)audio_procs_vec;
	for (auto &audio_procs : *vec) {
		if (strcmp(audio_procs.session_name, session_name) == 0)
			return &audio_procs;
	}
	return nullptr;
}

void clear_audio_procs_vec(HANDLE audio_procs_vec)
{
	std::vector<audio_processes_info> *vec =
		(std::vector<audio_processes_info> *)audio_procs_vec;
	for (auto &audio_procs : *vec) {
		free(audio_procs.pid_arr);
		free(audio_procs.x64_arr);
	}
	vec->clear();
}

void free_audio_procs_vec(HANDLE audio_procs_vec)
{
	std::vector<audio_processes_info> *vec =
		(std::vector<audio_processes_info> *)audio_procs_vec;
	clear_audio_procs_vec(vec);
	delete vec;
}

bool audio_procs_contain_pid(
	const struct audio_processes_info *const audio_procs, DWORD pid)
{
	for (size_t i = 0; i < audio_procs->count; i++) {
		if (audio_procs->pid_arr[i] == pid)
			return true;
	}
	return false;
}

// if realloc fails there's gonna be some bad, BAD voodoo
bool add_pid_to_audio_procs(struct audio_processes_info *const audio_procs,
			    DWORD pid, bool x64)
{
	if (audio_procs_contain_pid(audio_procs, pid)) {
		return true;
	}

	bool success = true;
	void *new_pid_arr;
	void *new_x64_arr;
	if (audio_procs->count > 0) {

		new_pid_arr = realloc(audio_procs->pid_arr,
				      (audio_procs->count + 1) * sizeof(DWORD));
		new_x64_arr = realloc(audio_procs->x64_arr,
				      (audio_procs->count + 1) * sizeof(bool));
	} else {

		new_pid_arr = malloc(sizeof(DWORD));
		new_x64_arr = malloc(sizeof(bool));
	}

	if (new_pid_arr) {
		audio_procs->pid_arr = (DWORD *)new_pid_arr;
		audio_procs->pid_arr[audio_procs->count] = pid;
	} else {
		success = false;
	}
	if (new_x64_arr) {
		audio_procs->x64_arr = (bool *)new_x64_arr;
		audio_procs->x64_arr[audio_procs->count] = x64;
	} else {
		success = false;
	}
	audio_procs->count++;
	return success;
}

/*--------[AUDIO PIPE]--------*/

HANDLE create_audio_pipes_list()
{
	return new std::list<audio_pipe>;
}

void refresh_audio_pipes(HANDLE audio_procs_vec, HANDLE audio_pipes_list,
			 const char *const new_session_name,
			 ipc_pipe_read_t callback, void *param)
{
	std::vector<audio_processes_info> *vec =
		(std::vector<audio_processes_info> *)audio_procs_vec;
	std::list<audio_pipe> *list = (std::list<audio_pipe> *)audio_pipes_list;

	size_t old_count = list->size();
	DWORD *old_pid_arr = nullptr;
	if (old_count > 0) {
		old_pid_arr = new DWORD[old_count];
		auto it = list->begin();
		for (int i = 0; i < old_count; i++) {
			old_pid_arr[i] = (*it).target_pid;
			it++;
		}
	}
	
	refresh_audio_procs(vec); // audio_procs is invalidated
	auto *audio_procs = get_audio_procs_from_name(vec, new_session_name);

	size_t new_count;
	const DWORD *new_pid_arr;
	if (!audio_procs) {
		new_count = 0;
		new_pid_arr = nullptr;
	} else {
		new_count = audio_procs->count;
		new_pid_arr = audio_procs->pid_arr;
	}
	for (size_t i = 0; i < new_count; i++) {
		bool match = false;
		for (size_t j = 0; j < old_count; j++) {
			if (new_pid_arr[i] == old_pid_arr[j]) {
				match = true;
				old_pid_arr[j] = NULL;
				break;
			}
		}
		if (!match)
			add_pipe_to_audio_pipes_list(list, new_pid_arr[i],
						     callback, param);
	}
	for (size_t i = 0; i < old_count; i++) {
		if (old_pid_arr[i] != NULL)
			remove_pid_from_audio_pipes_list(list, old_pid_arr[i]);
	}

	delete[] old_pid_arr;
}

size_t get_audio_pipes_count(HANDLE audio_pipes_list)
{
	std::list<audio_pipe> *list = (std::list<audio_pipe> *)audio_pipes_list;
	return list->size();
}

audio_pipe *get_audio_pipe(HANDLE audio_pipes_list, size_t index)
{
	std::list<audio_pipe> *list = (std::list<audio_pipe> *)audio_pipes_list;
	return &*std::next(list->begin(), index);
}

void add_pipe_to_audio_pipes_list(HANDLE audio_pipes_list, DWORD target_pid,
				  ipc_pipe_read_t callback, void *param)
{
	std::list<audio_pipe> *list = (std::list<audio_pipe> *)audio_pipes_list;
	auto &pipe = list->emplace_back();
	pipe.target_pid = target_pid;
	char name[64];
	snprintf(name, 64, AUDIO_PIPE_NAME "%lu", target_pid);
	ipc_pipe_server_start(&pipe.pipe_server, name, callback, param);
}

void remove_pipe_from_audio_pipes_list(HANDLE audio_pipes_list, size_t index)
{
	std::list<audio_pipe> *list = (std::list<audio_pipe> *)audio_pipes_list;
	auto it = std::next(list->begin(), index);
	ipc_pipe_server_free(&(*it).pipe_server);
	list->erase(it);
}

void remove_pid_from_audio_pipes_list(HANDLE audio_pipes_list, DWORD pid)
{
	std::list<audio_pipe> *list = (std::list<audio_pipe> *)audio_pipes_list;
	auto end = list->end();
	for (auto it = list->begin(); it != end;) {
		if ((*it).target_pid == pid) {
			ipc_pipe_server_free(&(*it).pipe_server);
			list->erase(it);
			return;
		} else {
			it++;
		}
	}
}

void clear_audio_pipes_list(HANDLE audio_pipes_list)
{
	std::list<audio_pipe> *list = (std::list<audio_pipe> *)audio_pipes_list;
	for (auto &pipe : *list) {
		ipc_pipe_server_free(&pipe.pipe_server);
	}
	list->clear();
}

void free_audio_pipes_list(HANDLE audio_pipes_list)
{
	std::list<audio_pipe> *list = (std::list<audio_pipe> *)audio_pipes_list;
	clear_audio_pipes_list(list);
	delete list;
}
