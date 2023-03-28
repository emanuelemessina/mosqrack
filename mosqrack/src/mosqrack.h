#pragma once

#include <iostream>
#include <stdio.h>
#include <cstring>
#include <filesystem>
#include <cstdarg>
#include <fstream>
#include <thread>
#include <mutex>

inline void console_log() {
	std::cout << std::endl;
}

template <typename... OtherMsgs>
inline void console_log(std::string msg, OtherMsgs... msgs)
{
	std::cout << msg.c_str() << " ";

	console_log(msgs...);
}

#define ASSERT_FILE_EXISTS(path, ...) \
if (!std::filesystem::exists(path)) {

#define OPEN_FSTREAM_AND_ASSERT_SUCCESS(fstream, path, mode) \
fstream.open(path, mode);\
if(!fstream.is_open()){

#define OTHERWISE( action ) action }

#define ABORT(retcode, ...) console_log("Aborted: ", __VA_ARGS__); return retcode;
