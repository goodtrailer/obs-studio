project(audio-hook)

set(audio-hook_HEADERS
	core-audio-capture.h
	wave-out-capture.h
	../audio-hook-info.h
	../hook-helpers.h
	../funchook.h
	../obfuscate.h)

set(audio-hook_SOURCES
	audio-hook.c
	core-audio-capture.cpp
	wave-out-capture.cpp
	../funchook.c
	../obfuscate.c)

if(MSVC)
	add_compile_options("$<IF:$<CONFIG:Debug>,/MTd,/MT>")
	set(win-capture_PLATFORM_DEPS
		w32-pthreads)
endif()

add_library(audio-hook MODULE
	${audio-hook_SOURCES}
	${audio-hook_HEADERS})

target_link_libraries(audio-hook
	${win-capture_PLATFORM_DEPS}
	libobs
	ipc-util
	psapi)

if (CMAKE_SIZEOF_VOID_P EQUAL 8)
	set(_output_suffix "64")
else()
	set(_output_suffix "32")
endif()

set_target_properties(audio-hook
	PROPERTIES
		FOLDER "plugins/win-capture"
		OUTPUT_NAME "audio-hook${_output_suffix}")

install_obs_datatarget(audio-hook "obs-plugins/win-capture")
