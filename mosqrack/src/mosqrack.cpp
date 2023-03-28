#pragma warning(disable : 6031)
#pragma warning(push)

#include "mosqrack.h"

#include "mosquitto/password_mosq.h"
#include "mosquitto/mosquitto_passwd.h"

#define NUM_THREADS 4
#define MAX_PATH_LEN 255

std::atomic<bool> hash_match; // thread sync
std::mutex thread_mtx;
bool thread_status[NUM_THREADS];

struct hash_match_args {
	int thread_id;
	std::string wordlist_path;
	size_t num_lines;
	const char* username;
	char* salt64;
	const char* desiredOutput;
};

void hashMatch(hash_match_args args) {
	
	thread_mtx.lock();
	thread_status[args.thread_id] = true; // i'm working
	thread_mtx.unlock();

	// open wordlist
	std::ifstream hWordlist;
	hWordlist.open(args.wordlist_path);

	// position seek to starting line

	size_t starting_line = args.thread_id * args.num_lines;
	
	if (starting_line > 0) {
		for (int i = 0; i < starting_line; i++) {
			hWordlist.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
		}
	}

	size_t current_line = starting_line;
	size_t last_line = starting_line + args.num_lines -1;

	std::string wpass;
	while (current_line <= last_line && std::getline(hWordlist, wpass)) {
		
		// thread sync
		if (hash_match) {
			thread_mtx.lock();
			thread_status[args.thread_id] = false; // i exited
			thread_mtx.unlock();
			return;
		}
		
		char output[MAX_BUFFER_LEN];
		output_new_password(output, args.username, wpass.c_str(), args.salt64, PW_DEFAULT_ITERATIONS);
		
		if (strncmp(args.desiredOutput, output, strlen(output)-1) == 0) {
			console_log("Hash match!", "Password:", wpass);
			// thread sync
			hash_match = true;
			thread_mtx.lock();
			thread_status[args.thread_id] = false; // i exited
			thread_mtx.unlock();
			return;
		}

		current_line++;
	}

	// not found
	// 
	// thread sync
	thread_mtx.lock();
	thread_status[args.thread_id] = false; // i exited
	thread_mtx.unlock();
}

int main(int argc, char** argv)
{
	std::string help =
		R"(Usage:
	moscrytto <hashfile> <wordlist>
	)";

	if (argc != 3) {
		std::cout << help << std::endl;
		return 0;
	}

	char hashfile[MAX_PATH_LEN];
	char wordlist[MAX_PATH_LEN];

	sprintf_s(hashfile, MAX_PATH_LEN, "%s", argv[1]);
	sprintf_s(wordlist, MAX_PATH_LEN, "%s", argv[2]);

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

	std::string hashfile_line;
	std::getline(hHashfile, hashfile_line);
	
	std::string username = hashfile_line.substr(0, hashfile_line.find(":"));
	
	char hflb[255];
	hashfile_line.copy(hflb, hashfile_line.length());
	strtok(hflb, "$");
	strtok(NULL, "$");

	char* salt64 = strtok(NULL, "$");

	console_log("Preparing threads...");
	size_t wordlist_lines = std::count(std::istreambuf_iterator<char>(hWordlist),
	std::istreambuf_iterator<char>(), '\n');

	size_t num_lines_per_thread = wordlist_lines / NUM_THREADS;
	size_t remainder_lines = wordlist_lines % NUM_THREADS;

	// set all threads as terminated
	for (int i = 0; i < NUM_THREADS; i++) {
		thread_status[i] = false;
	}
	// spawn threads
	std::vector<std::thread> threads;
	for (int i = 0; i < NUM_THREADS; i++) {
		hash_match_args args;
		args.thread_id = i;
		args.wordlist_path = wordlist;
		args.num_lines = num_lines_per_thread + (i == NUM_THREADS - 1 ? remainder_lines : 0); // add remainder lines for last thread
		args.username = username.c_str();
		args.salt64 = salt64;
		args.desiredOutput = hashfile_line.c_str();
		threads.push_back(std::thread(hashMatch, args));
	}

	console_log("Threads spawned. Searching...");

	// exit conditions
	while (true) {
		// check if thread found match
		if (hash_match)
			return 0;
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
		if (!stillWorking) // all thread exited
			ABORT(0, "None found, exiting.");
	}
}
