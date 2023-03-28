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


#include "password_mosq.h"
#include "mosquitto_passwd.h"

#include <stdio.h>
#include <stdlib.h>
#include <memory>

//static enum mosquitto_pwhash_type hashtype = pw_sha512_pbkdf2;
static enum mosquitto_pwhash_type hashtype = pw_sha512;

int output_new_password(char* outbuffer, const char* username, const char* password, char* salt64, int iterations)
{
	int rc;
	char* hash64 = NULL;
	struct mosquitto_pw pw;

	if (password == NULL) {
		fprintf(stderr, "Error: Internal error, no password given.\n");
		return 1;
	}
	memset(&pw, 0, sizeof(pw));

	pw.hashtype = hashtype;
	
	/* forced salt */
	unsigned int saltLen = SALT_LEN;
	unsigned char* salt;
	base64__decode(salt64, &salt, &saltLen);
	strcpy((char*)&pw.salt, (const char*)salt);

	/* false: no new pass */
	if (pw__hash(password, &pw, false, iterations)) {
		fprintf(stderr, "Error: Unable to hash password.\n");
		return 1;
	}

	/* 
	// original random salt
	rc = base64__encode(pw.salt, sizeof(pw.salt), &salt64);
	if (rc) {
		free(salt64);
		fprintf(stderr, "Error: Unable to encode salt.\n");
		return 1;
	}
	*/

	rc = base64__encode(pw.password_hash, sizeof(pw.password_hash), &hash64);
	if (rc) {
		//free(salt64);
		free(hash64);
		fprintf(stderr, "Error: Unable to encode hash.\n");
		return 1;
	}

	if (pw.hashtype == pw_sha512_pbkdf2) {
		sprintf(outbuffer, "%s:$%d$%d$%s$%s\n", username, hashtype, iterations, salt64, hash64);
	}
	else {
		sprintf(outbuffer, "%s:$%d$%s$%s\n", username, hashtype, salt64, hash64);
	}
	//free(salt64);
	free(hash64);

	return 0;
}