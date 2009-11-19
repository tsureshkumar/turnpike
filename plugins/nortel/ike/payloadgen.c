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
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <sys/socket.h>

/* Racoon Headers */
#include "racoon/var.h"
#include "racoon/isakmp_var.h"
#include "racoon/isakmp.h"
#include "racoon/isakmp_inf.h"
#include "racoon/ipsec_doi.h"
#include "racoon/handler.h"
#include "racoon/evt.h"
#include "racoon/remoteconf.h"
#include "racoon/schedule.h"

/* My headers */
#include "nortel_vmbuf.h"
#include "nortel_inf.h"
#include "payloadgen.h"
#include "utility.h"

#include "common/encrypt.h"

#define ENCRYPT_KEY "UJMNBVCDERTY"
#define KA_WAIT_NUM 5

#include "packets.h"

kaInf_t ka;

/* VID Generation */

static int appendNATVID(struct payload_list *pl, struct ph1handle *iph1)
{
    vchar_t *temp = NULL;
    caddr_t ptr = NULL;
    vchar_t *buf = NULL;
    caddr_t local = NULL, remote = NULL;
    struct payload_list *natVIDPayload = NULL;
    SHA_CTX *c = NULL;
    
   
    pl->next = (struct payload_list *) malloc(sizeof(struct payload_list));

    natVIDPayload = pl->next;
    
    natVIDPayload->next = NULL;
    natVIDPayload->prev = pl;
    
    natVIDPayload->payload = NULL;
    natVIDPayload->payload = nortel_vmalloc(26); /* TODO: Macro 26 */
    
    if(natVIDPayload->payload){

        memcpy(natVIDPayload->payload->v,"NaT-SI",6);
        natVIDPayload->payload_type = ISAKMP_NPTYPE_VID;

        /* Hash the remoteaddr:remoteport:localaddr:localport */
        
        if (iph1->remote->sa_family == AF_INET) {
		remote = (caddr_t) &(((struct sockaddr_in *) (iph1->remote))->sin_addr);
        } else
            return -1;
        
        if (iph1->local->sa_family == AF_INET) 
            local = (caddr_t)&((struct sockaddr_in *)iph1->local)->sin_addr;
        else
            return -1;
       
        plog(LLV_DEBUG, LOCATION, NULL, "In generating NAT VID: local %x remote %x\n",*(u_int32_t *)local,*(u_int32_t *)remote);

        buf = vmalloc(12); /* TODO: MACRO IT! */
        
        ptr = buf->v;  
        
        memcpy(ptr,(char *)&(((struct sockaddr_in *)iph1->local)->sin_addr),sizeof(u_int32_t));  
        ptr += sizeof(u_int32_t); 
        
        memcpy(ptr,(char *)&(((struct sockaddr_in *)iph1->local)->sin_port),sizeof(u_int16_t));
        ptr += sizeof(u_int16_t);
        
        memcpy(ptr,(char *)&(((struct sockaddr_in *)iph1->remote)->sin_addr), sizeof(u_int32_t));   
        ptr += sizeof(u_int32_t); 
        
        memcpy(ptr,(char *)&(((struct sockaddr_in *)iph1->remote)->sin_port), sizeof(u_int16_t));
        
        plog(LLV_DEBUG, LOCATION, NULL, "nortel private NAT address:\n");
        plogdump(LLV_DEBUG, buf->v, buf->l);
        
        /* Start Generate hash from buf */

        // TODO: Make hash generation into a function
         
        c = (SHA_CTX *)malloc(sizeof(*c));

        if(!c){
            plog(LLV_ERROR, LOCATION, NULL, " Memory Allocation Failed in Nortel Plugin \n"); 
            //        printf (" Memory Allocation Failed \n");
            return -1;
        }
        
        memset(c,0,sizeof(*c));

        SHA1_Init(c);
        
        SHA1_Update(c, buf->v, buf->l);
        
        if ((temp = nortel_vmalloc(SHA_DIGEST_LENGTH)) == 0)
            return -1;

        SHA1_Final((unsigned char *) temp->v, c);

        /* End of hash Generation */
        
        memcpy(natVIDPayload->payload->v + 6,temp->v,temp->l);
        natVIDPayload->payload->l = 6;
        plog(LLV_DEBUG, LOCATION, NULL, 
            "SHA final length:%zd Payload len till now:%zd\n",
            temp->l, natVIDPayload->payload->l); 
        natVIDPayload->payload->l+=temp->l;
        
        vfree(buf);
        vfree(temp);
        
        return 0;
    }
    return -1;
}

/* Return shud be Payloadlist_t */

int generateNortelVID(struct payload_list *pl, struct ph1handle *iph1)
{
    if(!iph1){
        plog(LLV_ERROR,LOCATION,NULL,"Looks like ph1 handle wasnot passed by racoon to plugin \n");
        return -1;
    }
    
    pl->next = pl->prev = NULL;

    pl->payload = NULL;
    pl->payload = nortel_vmalloc(10); /* TODO: MACRO 10 */
    if(pl->payload){

        memcpy(pl->payload->v,"BNEC\0\0\0\0",8);
        pl->payload->l = 8;
        pl->payload_type = ISAKMP_NPTYPE_VID;
        return appendNATVID(pl, iph1);
    }else
        return -1;
}

void ka_sched_callback(void *p)
{
    struct ph1handle *iph1 = (struct ph1handle *)p;
    int ret = 0;
        
    plog(LLV_DEBUG2, LOCATION, NULL, "Scheduler callback called \n");
    plog(LLV_DEBUG2, LOCATION, NULL, "Remote = %x Local = %x \n", ((struct sockaddr_in *)(iph1->remote))->sin_addr.s_addr, ((struct sockaddr_in *)(iph1->local))->sin_addr.s_addr  );

    ka.traf.local =((struct sockaddr_in *)(iph1->local))->sin_addr.s_addr; 

    ka.traf.remote = ((struct sockaddr_in *)(iph1->remote))->sin_addr.s_addr;

    ret = isNoTraffic(&ka.traf);
    
    switch(ret){
        
        case 1:
            plog(LLV_NOTIFY, LOCATION, NULL, "No traffic. Peer dead \n");
            /* tear down and inform UIs */
            evt_push(NULL, NULL, EVTT_PEER_NO_RESPONSE, NULL);
            
            goto end;
        case 0:
            plog(LLV_DEBUG, LOCATION, NULL, "traffic is going\n");
            ka.s = NULL; // reschedule for next checking.
            break;
        default:
            evt_push(NULL, NULL, EVTT_PEER_NO_RESPONSE, NULL);
            plog(LLV_ERROR, LOCATION, NULL,  "Error in retrieving packets sent\n");
            /* tear down and inform UIs */
            goto end;
    }
    
    /* Schedule a new timer. Packet transfer happens and peer is responding. */
    if(!ka.s)
    {
        plog(LLV_DEBUG2, LOCATION, NULL, "Rescheduling the timer for %d secs as traffic is going \n",ka.kainsec);
        ka.s = sched_new( /*CFG_KEEPALIVE_INTERVAL*/ ka.kainsec * 1.1 * KA_WAIT_NUM, ka_sched_callback, iph1);
        if(!ka.s){
            /* tear down and inform UIs */
            ;
        }
    }

end:    
    return;
    
}

/* Form the complete payload including gen header */

int generateNotifyPayload(vchar_t *payload, struct ph1handle *iph1, int type, u_int32_t kainsec)
{
    int spisiz = 0;
    struct isakmp_pl_n *n = NULL;
    int tlen = 0; 
    u_int32_t spi = 0;
    int error = 0;
    
    /* kill the already existing schedule. as peer responded with ka */
    if(ka.s){
        plog(LLV_DEBUG2, LOCATION, NULL, " Killing the schedule as peer responded.\n");
        /*update the packets sent in this interval. Function name is a misnomer! */
        isNoTraffic(&ka.traf);
        sched_kill(ka.s);
        ka.s = NULL;
    }
    /* Update the kainsecs for the sched callback */
    ka.kainsec = kainsec;
    
    spisiz =sizeof(spi);
    
    plog(LLV_DEBUG2, LOCATION, NULL,
                "Has come to Notify Payload.\n");
        
    tlen = sizeof(struct isakmp_pl_n) + spisiz;
    
    payload->v = malloc(tlen);
    payload->l = tlen;
    
    if (payload->v == NULL) { 
        plog(LLV_ERROR, LOCATION, NULL,
                "failed to get buffer to send.\n");
        return -1;
    }

    n = (struct isakmp_pl_n *)payload->v;
    
    memset(n, 0, sizeof(*n));
    
    n->h.np = ISAKMP_NPTYPE_NONE;
    n->h.len = htons(tlen);
    n->doi = htonl(iph1->rmconf->doitype);
    n->proto_id = 0; /* XXX to be configurable ? */

    n->spi_size = spisiz;
    n->type = htons(type);

    //FOR nortel NORTEL SPI SIZE IS 4 SPI IS 0
    memcpy(n + 1, &spi, sizeof(spi));
    
    ((struct sockaddr_in *)(iph1->remote))->sin_port = htons(500); 
    ((struct sockaddr_in *)(iph1->local))->sin_port = htons(500); 
    
    error = isakmp_info_send_common(iph1, payload, ISAKMP_NPTYPE_N, iph1->flags);
    
    if(!error){
        /* first time around schedule it here. Or re-schedule for further */
        if(!ka.s){
        plog(LLV_DEBUG2, LOCATION, NULL, "Rescheduling the timer for next check. Timer = %d \n",ka.kainsec);
            ka.s = sched_new( /*CFG_KEEPALIVE_INTERVAL*/ ka.kainsec * 1.1 * KA_WAIT_NUM , ka_sched_callback, iph1);
            if(!ka.s){
                /* tear down and inform UIs */
                ;
            }
        }

    }

    return error;

}

/* 
   grpname is grpname 
   */

int generateOpaqueID(vchar_t *grpname, vchar_t **opaque_id)
{
    // TODO: Make hash generation into a function
    
    SHA_CTX *c = (SHA_CTX *)malloc(sizeof(*c));

    if(!c){
        plog(LLV_ERROR,LOCATION,NULL," Memory Allocation Failed in Nortel Plugin \n"); 
//        printf (" Memory Allocation Failed \n");
        return -1;
    }

    memset(c,0,sizeof(*c));

    SHA1_Init(c);

    SHA1_Update(c, grpname->v, grpname->l);

    if (((*opaque_id) = nortel_vmalloc(SHA_DIGEST_LENGTH + 4)) == 0)
        return -1;

    SHA1_Final( (unsigned char *) (*opaque_id)->v, c);

    free(c);

    /* TODO: Should this Opaque ID be padded with 4 bytes of 0's (as done in bullpen). */
    return 0;
}

/*
   1. hash the password using SHA1
   2. Using the hash of 1 as key to hash username (grpname) with hmacsha

 */

int generatePresharedKey(vchar_t *grpname, vchar_t *encpass,  vchar_t **preshared_key) 
{
    vchar_t *hashed_password = NULL;// hashed password, SHA hashes are 160 bits long
    SHA_CTX *c = NULL;
    HMAC_CTX *hc = NULL;
    vchar_t *password = NULL;
    unsigned int l = 0;
    
    /* Decode the password */
    
    plog(LLV_DEBUG, LOCATION, NULL, "Encoded pass len %zd\n", encpass->l);

    password = malloc(sizeof(vchar_t));
    password->l = 512;
    password->v =malloc(password->l);
    
    if (password == NULL || password->v == NULL ) /* TODO: macro 512  as 2 * passlen*/
    {
        plog(LLV_ERROR, LOCATION, NULL, "ERROR : Alloc failed group passwd, restart machine");
        return -1;
    } 

    if(nortel_decode (encpass->v, 
                encpass->l, 
                password->v,
                &(password->l),
                ENCRYPT_KEY,
                strlen(ENCRYPT_KEY)) )
    {
        plog(LLV_ERROR, LOCATION, NULL, "ERROR : Unable to decrypt Group secret ");
	free(password->v);
       return -1; 
    }
    
    // TODO: Make hash generation into a function

    c = (SHA_CTX *)malloc(sizeof(*c));

    if(!c){
        plog(LLV_ERROR,LOCATION,NULL," Memory Allocation Failed in Nortel Plugin \n"); 
        //printf (" Memory Allocation Failed \n");
	free(password->v);
        return -1;
    }
    memset(c,0,sizeof(*c));

    SHA1_Init(c);

    SHA1_Update(c, password->v, password->l);

    if ((hashed_password = nortel_vmalloc(SHA_DIGEST_LENGTH)) == 0) {
	free(password->v);
        return -1;
    }

    SHA1_Final( (unsigned char *) hashed_password->v, c);

    free(c);

    /*HMAC Hash the grpname using the hashed password*/

    hc = (HMAC_CTX *)malloc(sizeof(*hc));

    if(!hc){
        plog(LLV_ERROR,LOCATION,NULL," Memory Allocation Failed in Nortel Plugin \n"); 
        //printf (" Memory Allocation Failed \n");
	nortel_vfree(hashed_password);
	free(password->v);
        return -1;
    }
    memset(hc,0,sizeof(*hc));

    HMAC_Init(hc, hashed_password->v, hashed_password->l, EVP_sha1());
    nortel_vfree(hashed_password);

    HMAC_Update (hc, (unsigned char *) grpname->v, grpname->l);

    if (((*preshared_key) = nortel_vmalloc(SHA_DIGEST_LENGTH)) == 0) {
	free(password->v);
        return -1;
    }

    HMAC_Final (hc,  (unsigned char *) (*preshared_key)->v, &l);
    (*preshared_key)->l = l;
    free(hc);

    if (SHA_DIGEST_LENGTH != (*preshared_key)->l) {
        plog(LLV_ERROR,LOCATION,NULL,"hmac sha1 length mismatch %zd.\n", (*preshared_key)->l); 
        //printf( "hmac sha1 length mismatch %zd.\n", (*preshared_key)->l);
	free(password->v);
        nortel_vfree(*preshared_key);
        return -1;
    }

    free(password->v);
    return 0;
}

