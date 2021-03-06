#include <Windows.h>
#include <Psapi.h>
#include <type_traits>
#include <initguid.h>
#include <mmdeviceapi.h>
#include <audioclient.h>
#include <stdio.h>
#include <intrin.h>
#include <mutex>

#include <ipc-util/pipe.h>
#include <util/threading.h>
#include <util/util_uint64.h>
#include <util/threading.h>
#include <media-io/audio-io.h>

#include "core-audio-capture.h"
#include "../audio-hook-info.h"

static ipc_pipe_client_t g_pipe_client = {0};

static HRESULT(WINAPI *g_original_get_buffer)(IUnknown *, UINT32,
					      BYTE **) = nullptr;

static HRESULT(WINAPI *g_original_release_buffer)(IUnknown *, UINT32,
						  DWORD) = nullptr;

static HRESULT(WINAPI *g_original_initialize)(IUnknown *, AUDCLNT_SHAREMODE,
					      DWORD, REFERENCE_TIME,
					      REFERENCE_TIME,
					      const WAVEFORMATEX *,
					      LPCGUID) = nullptr;

static IAudioRenderClient *g_audio_render_client = nullptr;
static IAudioClient *g_audio_client = nullptr;
static WAVEFORMATEX *g_wave_format = nullptr;
static BYTE *g_data = nullptr;

static inline uint64_t get_clockfreq()
{
	static bool have_clockfreq = false;
	static LARGE_INTEGER clock_freq;

	if (!have_clockfreq) {
		QueryPerformanceFrequency(&clock_freq);
		have_clockfreq = true;
	}

	return clock_freq.QuadPart;
}

uint64_t os_gettime_ns()
{
	LARGE_INTEGER current_time;
	double time_val;

	QueryPerformanceCounter(&current_time);
	time_val = (double)current_time.QuadPart;
	time_val *= 1000000000.0;
	time_val /= (double)get_clockfreq();

	return (uint64_t)time_val;
}

static bool init_pipe()
{
	ipc_pipe_client_free(&g_pipe_client);
	char new_name[64];
	sprintf(new_name, "%s%lu", AUDIO_PIPE_NAME, GetCurrentProcessId());

	if (!ipc_pipe_client_open(&g_pipe_client, new_name)) {
		return false;
	}
	return true;
}

template<typename T> static inline void safe_release(T **out_COM_obj)
{
	static_assert(std::is_base_of<IUnknown, T>::value,
		      "Object must implement IUnknown");
	if (*out_COM_obj)
		(*out_COM_obj)->Release();
	*out_COM_obj = nullptr;
}

static bool hook_COM(IUnknown *COM_obj, void *hook_func,
		     void **out_original_method, size_t offset)
{
	if (!COM_obj)
		return false;

	void **vtable = *((void ***)COM_obj);
	if (vtable[offset] == hook_func)
		return false;

	unsigned long old_protect = 0;
	if (!VirtualProtect(*(void **)(COM_obj), sizeof(void *),
			    PAGE_EXECUTE_READWRITE, &old_protect))
		return false;

	if (out_original_method)
		*out_original_method = vtable[offset];
	vtable[offset] = hook_func;

	return true;
}

inline bool try_pipe(ipc_pipe_client_t *client, void *buf, size_t size)
{
	for (int i = 0; i < AUDIO_PIPE_MAX_RETRY; i++) {
		if (ipc_pipe_client_write(client, buf, size))
			return true;
		init_pipe();
	}
	return false;
}

HRESULT WINAPI get_buffer_hook(IUnknown *This, UINT32 NumFramesRequested,
			       BYTE **ppData)
{
	HRESULT ret = g_original_get_buffer(This, NumFramesRequested, ppData);
	g_data = *ppData;
	return ret;
}

HRESULT WINAPI release_buffer_hook(IUnknown *This, UINT32 NumFramesWritten,
				   DWORD dwFlags)
{
	HRESULT ret =
		g_original_release_buffer(This, NumFramesWritten, dwFlags);
	if (NumFramesWritten == 0)
		return ret;

	size_t data_size =
		(size_t)NumFramesWritten * g_wave_format->nBlockAlign;
	size_t buffer_count =
		data_size / SAFE_DATA_SIZE + (data_size % SAFE_DATA_SIZE != 0);

	if (buffer_count > MAX_BUF_COUNT)
		return ret;

	BYTE buffer[SAFE_BUF_SIZE]{0};
	BYTE *data = buffer + sizeof(audio_metadata);

	// fill in metadata
	audio_metadata *md = (audio_metadata *)buffer;

	if (g_wave_format->cbSize < 22) {
		if (g_wave_format->wFormatTag == WAVE_FORMAT_IEEE_FLOAT)
			md->format = AUDIO_FORMAT_FLOAT;
		else if (g_wave_format->wBitsPerSample == 8)
			md->format = AUDIO_FORMAT_U8BIT;
		else if (g_wave_format->wBitsPerSample == 16)
			md->format = AUDIO_FORMAT_16BIT;
		else if (g_wave_format->wBitsPerSample == 32)
			md->format = AUDIO_FORMAT_32BIT;
		else
			md->format = AUDIO_FORMAT_UNKNOWN;

		md->layout = (speaker_layout)g_wave_format->nChannels;
	} else {
		auto *extensible = (WAVEFORMATEXTENSIBLE *)g_wave_format;

		GUID fmt = extensible->SubFormat;
		if (fmt == KSDATAFORMAT_SUBTYPE_IEEE_FLOAT)
			md->format = AUDIO_FORMAT_FLOAT;
		else if (fmt == KSDATAFORMAT_SUBTYPE_PCM) {
			if (g_wave_format->wBitsPerSample == 8)
				md->format = AUDIO_FORMAT_U8BIT;
			else if (g_wave_format->wBitsPerSample == 16)
				md->format = AUDIO_FORMAT_16BIT;
			else if (g_wave_format->wBitsPerSample == 32)
				md->format = AUDIO_FORMAT_32BIT;
			else
				md->format = AUDIO_FORMAT_UNKNOWN;
		} else {
			md->format = AUDIO_FORMAT_UNKNOWN;
		}

		DWORD layout = extensible->dwChannelMask;
		switch (layout) {
		case KSAUDIO_SPEAKER_2POINT1:
			md->layout = SPEAKERS_2POINT1;
			break;
		case KSAUDIO_SPEAKER_SURROUND:
			md->layout = SPEAKERS_4POINT0;
			break;
		case (KSAUDIO_SPEAKER_SURROUND | SPEAKER_LOW_FREQUENCY):
			md->layout = SPEAKERS_4POINT1;
			break;
		case KSAUDIO_SPEAKER_5POINT1_SURROUND:
			md->layout = SPEAKERS_5POINT1;
			break;
		case KSAUDIO_SPEAKER_7POINT1_SURROUND:
			md->layout = SPEAKERS_7POINT1;
			break;
		default:
			md->layout = (speaker_layout)g_wave_format->nChannels;
		}
	}
	md->samples_per_sec = g_wave_format->nSamplesPerSec;

	uint64_t now = os_gettime_ns();
	for (size_t i = 0; i < buffer_count; i++) {
		size_t offset = i * SAFE_DATA_SIZE;
		uint64_t frame_delay =
			NumFramesWritten - offset / g_wave_format->nBlockAlign;
		md->timestamp = now - util_mul_div64(frame_delay, (uint64_t)1e9,
						     md->samples_per_sec);
		size_t sub_data_size = min(SAFE_DATA_SIZE, data_size - offset);
		md->frames = (uint32_t)sub_data_size / g_wave_format->nBlockAlign;
		memcpy(data, g_data + offset, sub_data_size);
		try_pipe(&g_pipe_client, buffer, SAFE_BUF_SIZE);
	}
	return ret;
}

HRESULT WINAPI initialize_hook(IUnknown *This, AUDCLNT_SHAREMODE ShareMode,
			       DWORD StreamFlags,
			       REFERENCE_TIME hnsBufferDuration,
			       REFERENCE_TIME hnsPeriodicity,
			       const WAVEFORMATEX *pFormat,
			       LPCGUID AudioSessionGuid)
{
	*g_wave_format = *pFormat;
	return g_original_initialize(This, ShareMode, StreamFlags,
				     hnsBufferDuration, hnsPeriodicity, pFormat,
				     AudioSessionGuid);
}

bool hook_core_audio()
{
	bool success = false;
	if (FAILED(CoInitializeEx(NULL, COINIT_MULTITHREADED)))
		return success;

	IMMDeviceEnumerator *device_enum;
	IMMDevice *device;

	if (FAILED(CoCreateInstance(__uuidof(MMDeviceEnumerator), NULL,
				    CLSCTX_ALL, __uuidof(IMMDeviceEnumerator),
				    (void **)&device_enum)))
		goto out_uninitialize;

	if (FAILED(device_enum->GetDefaultAudioEndpoint(eRender, eMultimedia,
							&device)))
		goto out_release_enum;

	if (FAILED(device->Activate(__uuidof(IAudioClient), CLSCTX_ALL, NULL,
				    (void **)&g_audio_client)))
		goto out_release_device;

	if (FAILED(g_audio_client->GetMixFormat(&g_wave_format)))
		goto out_release_device;

	if (FAILED(g_audio_client->Initialize(
		    AUDCLNT_SHAREMODE_SHARED, AUDCLNT_STREAMFLAGS_NOPERSIST,
		    10000000LL, 0, g_wave_format, NULL)))
		goto out_release_device;

	if (FAILED(g_audio_client->GetService(__uuidof(IAudioRenderClient),
					      (void **)&g_audio_render_client)))
		goto out_release_device;

	success = true;
	hook_COM(g_audio_render_client, &get_buffer_hook,
		 (void **)&g_original_get_buffer, 3);
	hook_COM(g_audio_render_client, &release_buffer_hook,
		 (void **)&g_original_release_buffer, 4);
	hook_COM(g_audio_client, *initialize_hook,
		 (void **)&g_original_initialize, 3);
	init_pipe();
out_release_device:
	safe_release(&device);
out_release_enum:
	safe_release(&device_enum);
out_uninitialize:
	CoUninitialize();
	return success;
}

void unhook_core_audio()
{
	hook_COM(g_audio_render_client, g_original_get_buffer, nullptr, 3);
	hook_COM(g_audio_render_client, g_original_release_buffer, nullptr, 4);
	if (SUCCEEDED(CoInitializeEx(NULL, COINIT_MULTITHREADED))) {
		safe_release(&g_audio_render_client);
		safe_release(&g_audio_client);
		CoTaskMemFree(g_wave_format);
		CoUninitialize();
	}
	ipc_pipe_client_free(&g_pipe_client);
}
