/*-
 * Copyright 2016 Vsevolod Stakhov
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#ifndef SRC_LIBCRYPTOBOX_CATENA_CATENA_H_
#define SRC_LIBCRYPTOBOX_CATENA_CATENA_H_

/* Modes  */
#define PASSWORD_HASHING_MODE 0
#define KEY_DERIVATION_MODE   1
#define REGULAR 0
#define CLIENT 1

#define CATENA_HLEN 64

#ifdef  __cplusplus
extern "C" {
#endif

int
catena (const uint8_t *pwd, const uint32_t pwdlen,
		const uint8_t *salt, const uint8_t saltlen,
		const uint8_t *data, const uint32_t datalen,
		const uint8_t lambda, const uint8_t min_garlic,
		const uint8_t garlic, const uint8_t hashlen, uint8_t *hash);

/**
 * Simple interface for catena PBKDF
 * @param pwd password
 * @param pwdlen length of password
 * @param salt salt
 * @param saltlen length of salt
 * @param data additional data
 * @param datalen length of additional data
 * @param hash output hash
 * @return 0 if hash is generated, -1 in case of error
 */
int simple_catena (const uint8_t *pwd, const uint32_t pwdlen,
				   const uint8_t *salt, const uint8_t saltlen,
				   const uint8_t *data, const uint32_t datalen,
				   uint8_t hash[CATENA_HLEN]);

/**
 * Run a quick test on catena implementation
 */
int catena_test (void);

#ifdef  __cplusplus
}
#endif

#endif /* SRC_LIBCRYPTOBOX_CATENA_CATENA_H_ */
