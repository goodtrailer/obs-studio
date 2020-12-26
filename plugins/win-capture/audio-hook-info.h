#pragma once
#include <stdint.h>

#define AUDIO_PIPE_NAME "AudioHook_Pipe"
#define AUDIO_PIPE_MAX_RETRY 4
#define SAFE_BUF_SIZE (IPC_PIPE_BUF_SIZE - 8)
#define SAFE_DATA_SIZE (SAFE_BUF_SIZE - sizeof(struct audio_metadata))
#define MAX_BUF_COUNT 12


struct audio_metadata {
	enum speaker_layout layout;
	enum audio_format format;
	uint32_t samples_per_sec;
	uint64_t timestamp;
	uint32_t frames;
};
