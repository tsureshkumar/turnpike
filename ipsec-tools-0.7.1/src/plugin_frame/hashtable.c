
/************************************************************************************
 *   Copyright (c) 2005, Novell Inc.,                                                *
 *   All rights reserved.                                                            *
 *                                                                                   *
 *   Redistribution and use in source and binary forms, with or without              *
 *   modification, are permitted provided that the following conditions              *
 *   are met:                                                                        *
 *   1.  Redistributions of source code must retain the above copyright              *
 *       notice, this list of conditions and the following disclaimer.               *
 *   2.  Redistributions in binary form must reproduce the above copyright           *
 *       notice, this list of conditions and the following disclaimer in the         *
 *       documentation and/or other materials provided with the distribution.        *
 *   3.  Neither the name of the Novell nor the names of its contributors            *
 *       may be used to endorse or promote products derived from this software       *
 *       without specific prior written permission.                                  *
 *   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND *
 *   ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE           *
 *   IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE      *
 *   ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE *
 *   FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL      *
 *   DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS         *
 *   OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)           *
 *   HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT      *
 *   LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY       *
 *   OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF          *
 *   SUCH DAMAGE.                                                                    *
 *************************************************************************************/

#include <stdio.h>
#include <string.h>
#include <malloc.h>
#include <sys/types.h>

#include "config.h"
#include "misc.h"

#include "position.h"
#include "hashtable.h"
#include "common.h"
#include "framework.h"
#include "error.h"

static int get_hash_index(struct hookpoint *hp);

void init_hash_table()
{
	int i;

	for(i = 0; i < MAX_TURN_HASH_SIZE; i++)
		turnhash[i] = NULL;
}

void clear_hash_table()
{
	int i;
	struct hookdata *hd, *temp = NULL;

	for(i = 0; i < MAX_TURN_HASH_SIZE; i++)
	{
		for(hd = turnhash[i]; hd; hd = temp)
		{
			if(hd->hi)
				free(hd->hi);
			if(hd->hp)
			{
				if(hd->hp->keylen)
					free(hd->hp->key);
				free(hd->hp);
			}
			temp = hd->next;
			free(hd);
		}
		turnhash[i] = NULL;
	}
}

int dump_hash(void)
{
	int i;
	struct hookdata *hd;
	struct hookpoint *hp;
	for (i = 0; i < MAX_TURN_HASH_SIZE; i++)
	{
		if (!(hd = turnhash[i]))
			continue;
#if 0
		plog(LLV_DEBUG2, LOCATION, NULL, "Hash Bucket: %d\n", i);
#else
		printf("Hash Bucket: %d\n", i);
#endif

		while (hd)
		{
			hp = hd->hp;
#if 0
			plog(LLV_DEBUG2, LOCATION, NULL, "\n--------- Entry Info ---------\n");
#else
			printf("\n--------- Entry Info ---------\n");
#endif
			printf( "type = 0x%x, payloadtype = 0x%x, AttrOrPayloadSubtype = 0x%x, \
					Exchange = 0x%x, Message Index = 0x%x, Payload1 = 0x%x, Payload2 = 0x%x, \
					Keylen = 0x%x callback:%p\n",
					(unsigned int) hp->type,
					(unsigned int) hp->payloadtype,
					(unsigned int) hp->subtype,
					GET_EXCH(hp->position),
					GET_MIDX(hp->position),
					GET_PAYLOAD_1(hp->position),
					GET_PAYLOAD_2(hp->position),
					hp->keylen,
					hd->hi->callback);
			hd = hd->next;
		}
	}
	return 0;
}

static int get_hash_index(struct hookpoint *hp)
{
	u_int32_t hash_index = 0, temp = 0;
	size_t i;

	// For incoming paths: Mode(i), Position(j), type, payloadtype, Key are used for hashing
	// For outgoing paths: Mode(i), Position(j), type, payloadtype, AttrOrPayloadSubtype are used for hashing


	if ((temp = GET_EXCH(hp->position)) != ISAKMP_ETYPE_ALL) {
		hash_index |= SET_EXCH(temp);
	}
	if ((temp = GET_MIDX(hp->position)) != TPIKE_MIDX_ANY) {
		hash_index |= SET_MIDX(temp);
	}
	if (hp->type == PAYLOAD_TYPE) {
		hash_index ^= (hp->type ^ hp->payloadtype ^ hp->subtype);
	}
	else {
		hash_index ^= (hp->type ^ hp->payloadtype ^ ((hp->payloadtype == CONFIG_ATTRIB_TYPE)?hp->subtype:0));
	}
	if (GET_MIDX(hp->position) & TPIKE_MIDX_RECEIVE) {
		for (i = 0; (i + 3) <= hp->keylen; i+=sizeof(u_int32_t)) {
			temp ^= (((char *)(hp->key))[i] << 24) |
				(((char *)(hp->key))[i + 1] << 16) |
				(((char *)(hp->key))[i + 2] << 8) |
				(((char *)(hp->key))[i + 3]);
		}
		for (; i < hp->keylen; i++)
			temp |= ((char *)(hp->key))[i];
	}
	hash_index ^= temp;
	hash_index = hash_index % MAX_TURN_HASH_PRIME_SIZE;
	return hash_index;
}

/* TODO -Ramu : As of now the only wild card handled is etype. Extend/Rewrite this to others also */
static int get_handler_match_wild_card(struct hookpoint *hp, struct handlerinfo **hi )
{
	struct hookdata *hd;
	u_int16_t hash_index = 0;
	int status = TPIKE_ERR_HASH_MATCH_NOT_FOUND;
	int etype = 0;
	int is_all_phases_checked = 0;
	*hi = NULL;

	/*Logic: Considering only wild cards are etypes. For generic stuff this logic may be too narrow.
	 * 1. Determine whether the etype belongs to the class of phase1 or phase2.
	 * 2. Depending on 1 check either phase1 bucket or phase2 bucket.
	 * 3. If no match found in both these buckets check all phases bucket.
	 */
	etype = GET_EXCH(hp->position);

	if(etype == ISAKMP_ETYPE_IDENT || etype == ISAKMP_ETYPE_AGG || etype == ISAKMP_ETYPE_BASE || etype == ISAKMP_ETYPE_ALLPHASE1){
		//   etype = ISAKMP_ETYPE_ALLPHASE1;
		hash_index = MAX_TURN_HASH_PRIME_SIZE;

	}
	else
		if(etype == ISAKMP_ETYPE_QUICK || etype == ISAKMP_ETYPE_ALLPHASE2)
			//etype = ISAKMP_ETYPE_ALLPHASE2;
			hash_index = MAX_TURN_HASH_PRIME_SIZE + 1;
		else //all phases
			hash_index = MAX_TURN_HASH_PRIME_SIZE + 2;

wildcardloop:

	hd = turnhash[hash_index];

	/* As of now i am scanning for REKEYREQ_TYPE alone. Extend this for all other types */
	while(hd)
	{
		if(hd->hp && !memcmp(hd->hp, hp, sizeof(hd->hp->type) + sizeof(hd->hp->payloadtype) + sizeof(hd->hp->subtype) /*+ sizeof(u_int16_t)*/))
		{
			/* TODO: As this is always put into fixed buckets we need to check the position (and other variable params) also while matching.  */
			if (GET_MIDX (hp->position) == GET_MIDX(hd->hp->position) &&
					hd->hi->callback){
				(*hi) =  hd->hi;
				status = TPIKE_STATUS_SUCCESS;
				break;
			}
		}
		hd = hd->next;
	}

	if(status != TPIKE_STATUS_SUCCESS && is_all_phases_checked == 0 && hash_index != MAX_TURN_HASH_PRIME_SIZE + 2){
		/* Check in ALL phases bucket */
		hash_index = MAX_TURN_HASH_PRIME_SIZE + 2;
		is_all_phases_checked = 1;
		goto wildcardloop; //TODO: Remove this goto.

	}
	return status;
}

int get_handler_match_in_hash_bucket(struct hookpoint *hp, struct handlerinfo **hi )
{
	struct hookdata *hd;
	u_int16_t hash_index = 0;
	int status = TPIKE_ERR_HASH_MATCH_NOT_FOUND;

	*hi = NULL;

	//compute hash index
	hash_index = get_hash_index(hp);
	printf("Hash index in get_handler_match = %d\n",hash_index);
	//sanity check
	if(hash_index > MAX_TURN_HASH_SIZE - 1)
		return TPIKE_ERR_HASH_TABLE_OVERFLOW;

	hd = turnhash[hash_index];

	while(hd)
	{
		/*
			if(hd->hp && !memcmp(hd->hp, hp, sizeof(struct hookpoint) - sizeof(void *) -sizeof(hd->hp->keylen) - sizeof(hd->hp->isoptional) - sizeof(u_int16_t)))
			*/
		if(hd->hp && !memcmp(hd->hp, hp, sizeof(hd->hp->type) + sizeof(hd->hp->payloadtype) + sizeof(hd->hp->subtype) /*+ sizeof(u_int16_t)*/))
		{
			if(hp->payloadtype == CONFIG_ATTRIB_TYPE && hp->subtype == 3 /* SET */){
				if((hd->hp->keylen == hp->keylen) && (memcmp(hp->key, hd->hp->key, (size_t) hd->hp->keylen) == 0)){
					if(hd->hi->callback){
						(*hi) =  hd->hi;
						status = TPIKE_STATUS_SUCCESS;
						break;
					}

				}
			}
			else{

				if(hd->hi->callback){
					(*hi) =  hd->hi;
					status = TPIKE_STATUS_SUCCESS;
					break;
				}
			}
		}
		hd = hd->next;
	}

	if(status != TPIKE_STATUS_SUCCESS)
		status = get_handler_match_wild_card(hp,hi);

	return status;

}

u_int32_t insert_in_hash_bucket(struct hookpoint *hp, struct handlerinfo *hi, struct plugininfo *plugin)
{
	int hash_index = 0;
	int status = TPIKE_STATUS_SUCCESS;
	struct hookdata *hd = NULL;
	struct handlerinfo *hi_already = NULL;

	//compute hash index

	/* TODO - Ramu: As of now handle wildcards by assigning one bucket for allphase1, one for allphase2 and one for allphases. Later change them to take other params also. */

	switch(GET_EXCH(hp->position)){

		case ISAKMP_ETYPE_ALLPHASE1:

			hash_index = MAX_TURN_HASH_PRIME_SIZE;
			break;

		case ISAKMP_ETYPE_ALLPHASE2:

			hash_index = MAX_TURN_HASH_PRIME_SIZE + 1;
			break;

		case ISAKMP_ETYPE_ALL:

			hash_index = MAX_TURN_HASH_PRIME_SIZE + 2;
			break;

		default: /* Not a wild card case */
			hash_index = get_hash_index(hp);
	}


	//sanity check
	if(hash_index < 0 || hash_index > MAX_TURN_HASH_SIZE - 1)
	{
		status =  TPIKE_ERR_HASH_TABLE_OVERFLOW;
		goto end_func;
	}
#if 0
	plog(LLV_DEBUG2, LOCATION, NULL, "Inserting in %d\n",hash_index);
#else
	printf("Inserting in %d\n",hash_index);
#endif

	/* FIX:
	 *
	 * 'hi' was  used as second param which gets destroyed after
	 * the call to this function (becomes NULL as it is the first time
	 * insertion. So passing a temperory handlerinfo
	 * to check if it is already inserted
	 *
	 */

	if(get_handler_match_in_hash_bucket(hp, &hi_already) == 0 )
	{
		status = TPIKE_ERR_HOOK_ALREADY_REGISTERED;
		goto end_func;
	}

	if((hd = (struct hookdata *)malloc(sizeof(struct hookdata))) == NULL)
	{
		status = TPIKE_ERR_MEM_ALLOC_FAILED;
		goto end_func;
	}

	hd->hi = (struct handlerinfo *)malloc(sizeof(struct handlerinfo));
	if(hd->hi && hi )
		memcpy(hd->hi, hi, sizeof(struct handlerinfo));//TODO: For hprivdata, we need the length of the data, so that we malloc and copy the priv data locally
	else
	{
		status = TPIKE_ERR_MEM_ALLOC_FAILED;
		goto end_func;
	}

	hd->hp = (struct hookpoint *)malloc(sizeof(struct hookpoint));
	if(hd->hp && hp)
		memcpy(hd->hp, hp, sizeof(struct hookpoint));//TODO: For KEY, we need the length of the data, so that we malloc and copy the priv data locally
	else
	{
		status = TPIKE_ERR_MEM_ALLOC_FAILED;
		goto end_func;
	}
	if(hd->hp->keylen){
		// NOTE: KEY LEN IS COPIED IN PRV MEMCPY
		hd->hp->key = malloc(hd->hp->keylen);
		memcpy(hd->hp->key,hp->key,hd->hp->keylen);
	}
	hd->plugin = plugin; // back pointer to plugin

	hd->next = turnhash[hash_index];

	turnhash[hash_index] = hd;

end_func:
	if(status != TPIKE_STATUS_SUCCESS)
	{
		//cleanup all that we've malloced
		if (hd)
		{
			if(hd->hi)
			{
				free(hd->hi);
				hd->hi = NULL;
			}
			if(hd->hp)
			{
				free(hd->hp);
				hd->hp = NULL;
			}
			if(hd)
			{
				free(hd);
			}
		}
	}
	return status;
}
