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

#pragma warning(disable : 6031)
#pragma warning(push)

#include "mosqrack.h"
#include "timer.h"

#include "mosquitto/password_mosq.h"
#include "mosquitto/mosquitto_passwd.h"

#define NUM_THREADS 4
#define MAX_PATH_LEN 255
#define MAX_LINE_LEN 255

std::atomic<bool> hash_match; // thread sync
std::mutex thread_mtx;
bool thread_status[NUM_THREADS];

struct hash_match_args {
	int thread_id;
	std::stringstream wordlist_chunk;
	const char* username;
	char* salt64;
	const char* desiredOutput;
};

void hashMatch(hash_match_args* args) {
	
	// set working status
	thread_mtx.lock();
	thread_status[args->thread_id] = true; // i'm working
	thread_mtx.unlock();

	std::string wpass;
	while (std::getline(args->wordlist_chunk, wpass)) {
		
		// thread sync
		if (hash_match) {
			thread_mtx.lock();
			thread_status[args->thread_id] = false; // i exited
			thread_mtx.unlock();
			return;
		}
		
		char output[MAX_BUFFER_LEN];
		output_new_password(output, args->username, wpass.c_str(), args->salt64, PW_DEFAULT_ITERATIONS);
		
		if (strncmp(args->desiredOutput, output, strlen(output)-1) == 0) { // output contains a new line
			
			console_log("Hash match from thread[", args->thread_id, "]", "Password:", wpass);
			
			// set found and exited status
			hash_match = true;
			thread_mtx.lock();
			thread_status[args->thread_id] = false; // i exited
			thread_mtx.unlock();

			return;
		}
	}

	// not found

	// set exited status
	thread_mtx.lock();
	thread_status[args->thread_id] = false; // i exited
	thread_mtx.unlock();
}

int main(int argc, char** argv)
{
	// check args

	std::string help =
		R"(Usage:
	moscrytto <passwd_file> <wordlist_file>
	)";

	if (argc != 3) {
		std::cout << help << std::endl;
		return 0;
	}

	char hashfile[MAX_PATH_LEN];
	char wordlist[MAX_PATH_LEN];

	sprintf_s(hashfile, MAX_PATH_LEN, "%s", argv[1]);
	sprintf_s(wordlist, MAX_PATH_LEN, "%s", argv[2]);

	// open files

	ASSERT_FILE_EXISTS(hashfile);
	OTHERWISE(ABORT(1, "Aborted:", hashfile, "does not exist."));
	ASSERT_FILE_EXISTS(wordlist);
	OTHERWISE(ABORT(1, "Aborted:", wordlist, "does not exist."));

	std::fstream hHashfile;
	std::fstream hWordlist;

	OPEN_FSTREAM_AND_ASSERT_SUCCESS(hHashfile, hashfile, std::ios::in);
	OTHERWISE(ABORT(1, "Error opening", hashfile));
	OPEN_FSTREAM_AND_ASSERT_SUCCESS(hWordlist, wordlist, std::ios::in);
	OTHERWISE(ABORT(1, "Error opening", wordlist));

	// process files

	std::string hashfile_line;
	std::getline(hHashfile, hashfile_line);
	
	std::string username = hashfile_line.substr(0, hashfile_line.find(":"));
	
	char hflb[MAX_LINE_LEN];
	hashfile_line.copy(hflb, hashfile_line.length());
	strtok(hflb, "$");
	strtok(NULL, "$");

	char* salt64 = strtok(NULL, "$");

	size_t worlist_size = std::filesystem::file_size(wordlist);
	size_t per_thread_wordlist_chunk_size = worlist_size / NUM_THREADS;
		
	// start timer
	
	Timer<std::chrono::seconds, std::chrono::steady_clock> clock;
	clock.tick();

	// spawn threads
	
	console_log("Preparing threads...");

	std::vector<std::thread> threads;
	std::vector<hash_match_args*> h_args;
	int currThreadId = 0;
	
	for (; currThreadId < NUM_THREADS; currThreadId++) {

		// set all threads as terminated
		thread_status[currThreadId] = false;

		// hold stop spawning condition
		bool noMoreThreads = false;

		// populate thread args
		h_args.push_back(new hash_match_args);
		hash_match_args* args = h_args[currThreadId];

		args->thread_id = currThreadId;
		args->username = username.c_str();
		args->salt64 = salt64;
		args->desiredOutput = hashfile_line.c_str();

		// read chunk and store in arg
		// fstream will increment file pointer so next thread will begin from first line of next chunk
		// in particular the last thread will take care of reading until eof
				
		char* read_chunk = (char*) malloc((per_thread_wordlist_chunk_size+1)*sizeof(char)); // alloc chunck size
		if (!hWordlist.read(read_chunk, per_thread_wordlist_chunk_size)) { noMoreThreads = true; } // read per thread chunk size
		read_chunk[hWordlist.gcount()] = 0; // null terminate buff
		args->wordlist_chunk << read_chunk; // append read to chunk buff content
		
		read_chunk = (char*) malloc(MAX_LINE_LEN * sizeof(char)); // alloc a line
		if (!hWordlist.getline(read_chunk, MAX_LINE_LEN)) { noMoreThreads = true; } // read until new line
		read_chunk[hWordlist.gcount()] = 0;
		args->wordlist_chunk << read_chunk;

		if (currThreadId == NUM_THREADS - 1) { // last thread -> read until eof 
			while (hWordlist.getline(read_chunk, MAX_LINE_LEN)) { // read_chunk is already allocated with MAX_LINE_LEN
				read_chunk[hWordlist.gcount()] = 0;
				args->wordlist_chunk << read_chunk;
			}
		}
		
		// start and push thread
		threads.push_back(std::thread(hashMatch, args));

		// check whether to stop spwaning threads
		if (noMoreThreads) {
			break;
		}
	}

	console_log("Spawned", currThreadId+1, "threads.", "Searching...");

	// main thread: check for exit conditions

	while (true) {

		// check if thread found match
		
		if (hash_match) {
			clock.tock();
			console_log("Elapsed:", clock.elapsed(), "s.");
			// all threads will terminate upon reading the match status
			for (int i = 0; i < NUM_THREADS; i++) {
				threads[i].join();
			}
			return 0;
		}
		
		// check if none found
		
		bool stillWorking = false;
		
		for (int i = 0; i < NUM_THREADS; i++) {
		
			thread_mtx.lock();

			if (thread_status[i]) { // thread still working
				stillWorking = true;
				thread_mtx.unlock();
				break;
			}

			thread_mtx.unlock();
		}
		
		if (!stillWorking) { // all thread exited
			clock.tock();
			console_log("Elapsed:", clock.elapsed());
			ABORT(0, "None found, exiting.");
		}
	}
}
