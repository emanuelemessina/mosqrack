/*
Copyright (c) 2023 Emanuele Messina <emanuelemessina.em@gmail.com>
All rights reserved. This program and the accompanying materials
are made available under the terms of the Eclipse Public License 2.0
and Eclipse Distribution License v1.0 which accompany this distribution.
The Eclipse Public License is available at
   https://www.eclipse.org/legal/epl-2.0/
and the Eclipse Distribution License is available at
  http://www.eclipse.org/org/documents/edl-v10.php.
SPDX-License-Identifier: EPL-2.0 OR BSD-3-Clause
*/

#pragma once

#include <iostream>
#include <stdio.h>
#include <cstring>
#include <filesystem>
#include <cstdarg>
#include <fstream>
#include <thread>
#include <mutex>

// private overloads
inline void _console_log() {
	std::cout << std::endl;
}
inline void _console_log(std::string str) {
	std::cout << str.c_str();
}
template <typename T>
inline void _console_log(T unk) {
	std::cout << unk;
}

// public

// single item
template <typename Tf>
inline void console_log(Tf item)
{
	_console_log(item);
	_console_log();
}
// variadic
template <typename Tf, typename ...Ts>
inline void console_log(Tf msg, Ts... msgs)
{
	_console_log(msg);
	_console_log(" ");
	console_log(msgs...);
}

#define ASSERT_FILE_EXISTS(path, ...) \
if (!std::filesystem::exists(path)) {

#define OPEN_FSTREAM_AND_ASSERT_SUCCESS(fstream, path, mode) \
fstream.open(path, mode);\
if(!fstream.is_open()){

#define OTHERWISE( action ) action }

#define ABORT(retcode, ...) console_log("Aborted: ", __VA_ARGS__); return retcode;
