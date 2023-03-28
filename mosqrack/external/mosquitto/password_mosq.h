#ifndef PASSWORD_COMMON_H
#define PASSWORD_COMMON_H
/*
Copyright (c) 2012-2020 Roger Light <roger@atchoo.org>
All rights reserved. This program and the accompanying materials
are made available under the terms of the Eclipse Public License 2.0
and Eclipse Distribution License v1.0 which accompany this distribution.
The Eclipse Public License is available at
   https://www.eclipse.org/legal/epl-2.0/
and the Eclipse Distribution License is available at
  http://www.eclipse.org/org/documents/edl-v10.php.
SPDX-License-Identifier: EPL-2.0 OR BSD-3-Clause
Contributors:
   Roger Light - initial implementation and documentation.
*/

#include <stdbool.h>

enum mosq_err_t {
	MOSQ_ERR_AUTH_CONTINUE = -4,
	MOSQ_ERR_NO_SUBSCRIBERS = -3,
	MOSQ_ERR_SUB_EXISTS = -2,
	MOSQ_ERR_CONN_PENDING = -1,
	MOSQ_ERR_SUCCESS = 0,
	MOSQ_ERR_NOMEM = 1,
	MOSQ_ERR_PROTOCOL = 2,
	MOSQ_ERR_INVAL = 3,
	MOSQ_ERR_NO_CONN = 4,
	MOSQ_ERR_CONN_REFUSED = 5,
	MOSQ_ERR_NOT_FOUND = 6,
	MOSQ_ERR_CONN_LOST = 7,
	MOSQ_ERR_TLS = 8,
	MOSQ_ERR_PAYLOAD_SIZE = 9,
	MOSQ_ERR_NOT_SUPPORTED = 10,
	MOSQ_ERR_AUTH = 11,
	MOSQ_ERR_ACL_DENIED = 12,
	MOSQ_ERR_UNKNOWN = 13,
	MOSQ_ERR_ERRNO = 14,
	MOSQ_ERR_EAI = 15,
	MOSQ_ERR_PROXY = 16,
	MOSQ_ERR_PLUGIN_DEFER = 17,
	MOSQ_ERR_MALFORMED_UTF8 = 18,
	MOSQ_ERR_KEEPALIVE = 19,
	MOSQ_ERR_LOOKUP = 20,
	MOSQ_ERR_MALFORMED_PACKET = 21,
	MOSQ_ERR_DUPLICATE_PROPERTY = 22,
	MOSQ_ERR_TLS_HANDSHAKE = 23,
	MOSQ_ERR_QOS_NOT_SUPPORTED = 24,
	MOSQ_ERR_OVERSIZE_PACKET = 25,
	MOSQ_ERR_OCSP = 26,
	MOSQ_ERR_TIMEOUT = 27,
	MOSQ_ERR_RETAIN_NOT_SUPPORTED = 28,
	MOSQ_ERR_TOPIC_ALIAS_INVALID = 29,
	MOSQ_ERR_ADMINISTRATIVE_ACTION = 30,
	MOSQ_ERR_ALREADY_EXISTS = 31,
};

enum mosquitto_pwhash_type {
	pw_sha512 = 6,
	pw_sha512_pbkdf2 = 7,
};

#define SALT_LEN 12
#define PW_DEFAULT_ITERATIONS 101

struct mosquitto_pw {
	unsigned char password_hash[64]; /* For SHA512 */
	unsigned char salt[SALT_LEN];
	int iterations;
	enum mosquitto_pwhash_type hashtype;
	bool valid;
};

int pw__hash(const char* password, struct mosquitto_pw* pw, bool new_password, int new_iterations);
int pw__memcmp_const(const void* ptr1, const void* b, size_t len);
int base64__encode(unsigned char* in, unsigned int in_len, char** encoded);
int base64__decode(char* in, unsigned char** decoded, unsigned int* decoded_len);

#endif