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
#include <sys/types.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <sys/sysctl.h>
#include <err.h>
#include <netinet/in.h>

#include "net/pfkeyv2.h"

#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <errno.h>
#include <netdb.h>
#include <fcntl.h>
#include <dirent.h>
#include <time.h>

/* My headers */
#include "nortel_vmbuf.h"
#include "nortel_inf.h"
#include "callbacks.h"
#include "utility.h"
#include "packets.h"

#define PATH_IPSEC_H <netinet/ipsec.h>

/* Racoon Headers */
#include "racoon/vmbuf.h"
#include "racoon/isakmp_var.h"
#include "racoon/isakmp.h"
#include "racoon/nattraversal.h"
#include "libipsec/libpfkey.h"


static int create_pfkey_socket(){
    
    struct timeval tv;
    int so = 0;
    tv.tv_sec = 1;
    tv.tv_usec = 0;

    if ((so = socket(PF_KEY, SOCK_RAW, PF_KEY_V2)) < 0) 
        return -1;

    if (setsockopt(so, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0) 
        return -1;
    
    return so;
    
}


static int send_sadb_dump(int so){
    
    struct sadb_msg msg;

    msg.sadb_msg_version = PF_KEY_V2;
    msg.sadb_msg_type = SADB_DUMP;
    msg.sadb_msg_errno = 0;
    msg.sadb_msg_satype = SADB_SATYPE_UNSPEC;
    msg.sadb_msg_len = PFKEY_UNIT64(sizeof(msg));
    msg.sadb_msg_reserved = 0;
    msg.sadb_msg_seq = 0;
    msg.sadb_msg_pid = getpid();

    if ((send(so, (char *)&msg, sizeof(msg), 0)) < 0) 
        return -1;
    
    return 0;
}


static int get_traffic_details(struct sadb_msg *m, traffic_t *t)
{
    caddr_t mhp[SADB_EXT_MAX + 1];
    struct sadb_lifetime *m_lftc;
    struct sadb_address *m_saddr, *m_daddr;
    struct sockaddr *src, *dst;
    u_int32_t srcip, dstip;

    /* check pfkey message. */
    if (pfkey_align(m, mhp)) 
        return -1;
    
    if (pfkey_check(mhp)) 
        return -1;
    
    m_lftc = (struct sadb_lifetime *)mhp[SADB_EXT_LIFETIME_CURRENT];
    m_saddr = (struct sadb_address *)mhp[SADB_EXT_ADDRESS_SRC];
    m_daddr = (struct sadb_address *)mhp[SADB_EXT_ADDRESS_DST];

    /* Existency check */
    if (m_saddr == NULL || m_daddr == NULL) 
        return -1;
    
    /* source address */
    src=((struct sockaddr *)(m_saddr + 1)); 
    srcip = ((struct sockaddr_in *)(src))->sin_addr.s_addr;

    /* destination address */
    dst=((struct sockaddr *)(m_daddr + 1)); 
    dstip = ((struct sockaddr_in *)(dst))->sin_addr.s_addr;
    
    /* lifetime */
    if (m_lftc != NULL) {
        
        /* OUT */
        if(srcip == t->local && dstip == t->remote)
            t->outbytes = m_lftc->sadb_lifetime_bytes;
        
        /* IN */
        if(srcip == t->remote && dstip == t->local )
            t->inbytes = m_lftc->sadb_lifetime_bytes;
        
        return 0;
        
    }

    return -1;
}

static int recv_sadb_resp(int so, traffic_t *t)
{
    u_char rbuf[1024 * 32];	/* XXX: Enough ? Should I do MSG_PEEK ? */
    ssize_t l;
    struct sadb_msg *msg;

    msg = (struct sadb_msg *)rbuf;
    do {
        if ((l = recv(so, rbuf, sizeof(rbuf), 0)) < 0) 
            return -1;
        

        if (PFKEY_UNUNIT64(msg->sadb_msg_len) != l) 
            return -1;
        
        if(msg->sadb_msg_errno != 0)
            return -1;
        
        if(get_traffic_details(msg,t) <0)
            return -1;

    } while (msg->sadb_msg_errno || msg->sadb_msg_seq);

    return (0);
}

/*
static int dump_traffic(traffic_t *t)
{

    printf("\nOut Bytes: %f \n", t->outbytes);
    printf("\nIn Bytes: %f \n", t->inbytes);
    return 0;
    
}
*/

/*
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

int main(){

    int so = 0;
    traffic_t t ={0};
    struct in_addr local, remote;

    so = create_pfkey_socket();
    send_sadb_dump(so);

    inet_aton("164.99.171.82", &local) ;

    t.local= local.s_addr;

    inet_aton("130.57.7.245", &remote) ;
    t.remote= remote.s_addr;

    printf("Calling recv_sadb_resp with %x %x\n", t.local, t.remote);
    recv_sadb_resp(so, &t);

    dump_traffic(&t);

    return 0;
}
*/

/* Returns 1 if no traffic. 0 if traffic and -1 on error */
/* t is updated on return */
int isNoTraffic(traffic_t *t)
{
    double orig_out = t->outbytes;
    double orig_in = t->inbytes;
    int so =0;
    
    /* TODO: Can be made to be a persistet socket */
    if((so = create_pfkey_socket()) <0)
        return -1;
    
    if(send_sadb_dump(so)<0)
    {
	close(so);
	return -1;
    }
    
    if(recv_sadb_resp(so, t)<0)
    {
	close(so);
        return -1;
    }
    
    close(so);
    
    plog(LLV_DEBUG, LOCATION, NULL, "Orig Outbytes = %f, new outbytes = %f \n", orig_out, t->outbytes);
    plog(LLV_DEBUG, LOCATION, NULL, "Orig Inbytes = %f, new inbytes = %f \n", orig_in, t->inbytes);

    if(orig_out == t->outbytes && orig_in == t->inbytes)
        return 1; // No traffic.
    else
        return 0;
    
}
