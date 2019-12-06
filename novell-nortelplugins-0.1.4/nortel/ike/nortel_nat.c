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
#include <inttypes.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define PATH_IPSEC_H <netinet/ipsec.h>
#include <libipsec/libpfkey.h>
#include <racoon/admin.h>
#include <racoon/schedule.h>


/* My headers */
#include "nortel_vmbuf.h"
#include "nortel_inf.h"
#include "callbacks.h"
#include "utility.h"

#define ENABLE_NATT

#include "racoon/handler.h"
#include "racoon/isakmp.h"
#include "racoon/nattraversal.h"

#include "common/plog.h"
#include "nortel_inf.h"
#include "nortel_nat.h"

void client_keepalive_add(
	struct sockaddr *NatSrc,
	struct sockaddr *NatDst,
	struct ph1handle *iph1
);

void client_ka_remove(struct ph1handle *iph1);

int
nortel_nat_enable_natt (struct nortelHandle *h_nortel,
                        struct isakmp_data *data)
{
   struct ph1handle *iph1 = nortel_get_ph1_handle (h_nortel);
	struct sockaddr_in src, dst;
   uint32_t gateway_ip = h_nortel->cfg->gatewayIP;
   struct sockaddr_in remote;

   if(!data)
      return -1;

   if (! iph1->natt_options)
      iph1->natt_options = (struct ph1natt_options *) malloc (sizeof (*iph1->natt_options));

   if (! iph1->natt_options) {
      plog (LLV_ERROR, LOCATION, NULL,
            "Allocating memory for natt_options failed!\n");
      return -1;
   }
   
   if(data->lorv) {

      memcpy(iph1->natt_options, data + 1, data->lorv);
      iph1->natt_flags |= NAT_ANNOUNCED;
      iph1->natt_flags |= NAT_DETECTED;

      extern void nortel_natt_float_ports (struct ph1handle *);
      
      nortel_natt_float_ports (iph1);
      
      memset (&src, 0, sizeof (src));	
      memset (&dst, 0, sizeof (dst));	
      memset (&remote, 0, sizeof (remote));
      remote.sin_family = AF_INET;
      remote.sin_addr.s_addr = gateway_ip;
      client_keepalive_add ( (struct sockaddr *) &iph1->local, (struct sockaddr *) &remote, iph1);
      
      plog (LLV_INFO, LOCATION, NULL,
            "Added CLIENT KEEP ALIVE!\n");
	
   }

   return 0;
}
/*
 *  All routines related to client keepalive
 *
 */

static int ka_max_retry = 5;
static struct sched *scr_c = NULL;		/* schedule for resend */

time_t nortel_keepalive_interval = 20;
int nortel_keepalive_max_retransmission = 5;

#define CFG_KEEPALIVE_MAX_RETRANSMISSION 18
#define NORTEL_KEEPALIVE_INTERVAL 18

vchar_t *ka_sendbuf = NULL;
void isakmp_client_ka(void *p);

void isakmp_client_ka_send(struct ph1handle *iph1)
{

   //iph1->ka_max_retry--;
	
   if(ka_max_retry <= 0){
      //force_racoon_shutdown();
      plog(LLV_NOTIFY, LOCATION, NULL,
           "Server is not responding to Client keepalive , disconnecting ........\n");
      return;
   }

   /* Once again schedule client keepalive timer*/   
   scr_c = sched_new( nortel_keepalive_interval , isakmp_client_ka, iph1);

   /* HDR only */
   if (isakmp_send(iph1, ka_sendbuf) < 0) {
      VPTRINIT(ka_sendbuf);
      plog(LLV_NOTIFY, LOCATION, NULL,
           "Failed to send Client keepalive ,try again\n");
      return;
   }      
       		
   return;
}//isakmp_client_ka

void isakmp_client_ka(void *p)
{
   isakmp_client_ka_send((struct ph1handle *)p);

   return;

}
             

void client_keepalive_add(struct sockaddr *NatSrc,
                          struct sockaddr *NatDst,
                          struct ph1handle *iph1)
	
{
   struct isakmp *isakmp;
   //int tlen = sizeof(struct isakmp);
   if (scr_c != NULL)
      client_ka_remove (iph1);
   scr_c = sched_new( nortel_keepalive_interval , isakmp_client_ka, iph1);

   if(ka_sendbuf) {
      vfree(ka_sendbuf);
      ka_sendbuf = NULL;
   }

   if ((ka_sendbuf = vmalloc(sizeof(struct isakmp) + 4)) == NULL){
      plog(LLV_ERROR, LOCATION, NULL, "memory allocation failed while adding client keepalive \n");
      return;
   }
			

   /* create isakmp header */
   /* msgid and flags are set to zero in vmalloc*/
   memset (ka_sendbuf->v, 0, sizeof (struct isakmp) + 3);
   isakmp = (struct isakmp *)ka_sendbuf->v;
   memcpy(&isakmp->i_ck, &iph1->index.i_ck, sizeof(cookie_t));
   memcpy(&isakmp->r_ck, &iph1->index.r_ck, sizeof(cookie_t));
   isakmp->np = 0x00 ;  // no next payload

   /*For keepalive set major and minor version to 9 and 9*/
   ISAKMP_SETMAJORV(isakmp->v,0x09);
   ISAKMP_SETMINORV(isakmp->v,0x09);
	
   isakmp->etype = ISAKMP_ETYPE_NONE;
   //isakmp->flags = iph1->flags; no need to set flags
   // commented comparing with win
   // isakmp->len   = htonl(tlen);
   isakmp->len   = 0;
   return;
		
}


	
/*
 * reset client keepalive timer 
 */
void reset_client_ka_timer( struct ph1handle *iph1)
{
   ka_max_retry = nortel_keepalive_max_retransmission;
   return;
}

/*
 * remove client keepalive timer
 */

void client_ka_remove( struct ph1handle *iph1)
{
   if(ka_sendbuf) {
      vfree(ka_sendbuf);
      ka_sendbuf = NULL;
   }
		
   sched_kill(scr_c);
   plog(LLV_INFO, LOCATION, NULL,
        "Removing client keepalive \n");

   return;
}




