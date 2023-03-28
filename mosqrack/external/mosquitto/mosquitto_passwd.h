#pragma once

#define MAX_BUFFER_LEN 65500
#define SALT_LEN 12

int output_new_password(char* outbuffer, const char* username, const char* password, char* salt64, int iterations);
