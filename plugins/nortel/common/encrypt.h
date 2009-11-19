/*
 * Copyright (C) 2005-2009 Novell, Inc.
 * 
 * All rights reserved.
 * 
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, contact Novell, Inc.
 * 
 * To contact Novell about this file by physical or electronic mail,
 * you may find current contact information at www.novell.com.
 */
#ifndef __VPNCENCRYPT_H
#define __VPNCENCRYPT_H

#include <openssl/des.h>

#define ENCRYPT_KEY "UJMNBVCDERTY"

int nortel_decode (char *cipher, int cipherlen, char *decode, size_t *decodelen,char *key, int keylen);
int nortel_encode (const char *clear, int clearlen, char *encode, int *encodelen,char *key, int keylen);

#endif

