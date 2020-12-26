#pragma once
#include <Windows.h>
#include <ipc-util/pipe.h>
#include "audio-hook-info.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Audio processes are grouped by any with the same session_name.
 * display_name is taken from a random process from the group.
 * AFAIK the display name is the same for all of them anyways.
 */
struct audio_processes_info {
	DWORD *pid_arr;
	bool *x64_arr;
	size_t count;
	wchar_t *display_name;
	char session_name[MAX_PATH];
};

struct audio_pipe {
	ipc_pipe_server_t pipe_server;
	DWORD target_pid;
};

/*--------[AUDIO PROC]--------*/

HANDLE create_audio_procs_vec();

bool refresh_audio_procs(HANDLE audio_procs_vec);

size_t get_audio_procs_count(HANDLE audio_procs_vec);

struct audio_processes_info *get_audio_procs(HANDLE audio_procs_vec,
					     size_t index);

struct audio_processes_info *
get_audio_procs_from_name(HANDLE audio_procs_vec,
			  const char *const session_name);

void clear_audio_procs_vec(HANDLE audio_procs_vec);

void free_audio_procs_vec(HANDLE audio_procs_vec);

bool audio_procs_contain_pid(
	const struct audio_processes_info *const audio_procs, DWORD pid);

bool add_pid_to_audio_procs(struct audio_processes_info *const audio_procs,
			    DWORD pid, bool x64);

/*--------[AUDIO PIPE]--------*/

HANDLE create_audio_pipes_list();

void refresh_audio_pipes(HANDLE audio_procs_vec, HANDLE audio_pipes_list,
			 const char *const new_session_name,
			 ipc_pipe_read_t callback, void *param);

size_t get_audio_pipes_count(HANDLE audio_pipes_list);

struct audio_pipe *get_audio_pipe(HANDLE audio_pipes_list, size_t index);

void add_pipe_to_audio_pipes_list(HANDLE audio_pipes_list, DWORD target_pid,
				  ipc_pipe_read_t callback, void *param);

void remove_pipe_from_audio_pipes_list(HANDLE audio_pipes_list, size_t index);

void remove_pid_from_audio_pipes_list(HANDLE audio_pipes_list, DWORD pid);

void clear_audio_pipes_list(HANDLE audio_pipes_list);

void free_audio_pipes_list(HANDLE audio_pipes_list);

#ifdef __cplusplus
}
#endif
