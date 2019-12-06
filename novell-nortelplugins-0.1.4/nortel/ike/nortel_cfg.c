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


/* My headers */
#include "nortel_vmbuf.h"
#include "nortel_inf.h"
#include "callbacks.h"
#include "utility.h"

#include "racoon/handler.h"
#include "plugin_frame/common.h"
#include "racoon/isakmp.h"
#include "racoon/nattraversal.h"

#include "common/plog.h"
#include "nortel_nat.h"

static struct isakmp_data * 
nortel_cfg_set_nat_keepalive (struct nortelHandle * h_nortel,
                              struct isakmp_data *attr);

inline boolean_t
nortel_cfg_split_tunnel_mode (struct nortelHandle * h_nortel)
{
   const char * env_split_tunneling =  getenv ("NORTEL_ENABLE_SPLIT_TUNNEL") ;
   boolean_t enable_split_tunneling = env_split_tunneling && strncasecmp (env_split_tunneling, "yes", 3) == 0 ? TRUE : FALSE;

   if (h_nortel == NULL)
      return TRUE;

   /* user preference takes precedence */
   if (env_split_tunneling != NULL)
      return enable_split_tunneling;

   /* server forces to do split tunelling */
   if (h_nortel->rt_list && 
       h_nortel->assignedIPAddr != 0 &&
       h_nortel->rt_list->l > 0)
      return TRUE;

   return FALSE;
}


extern int pfkey_add_policy_to_SPD (struct sockaddr * src,
                                    u_int prefs,
                                    struct sockaddr * dst,
                                    u_int prefd,
                                    u_int proto,
                                    ipsec_policy_t pin,
                                    ipsec_policy_t pout,
                                    u_int32_t seq);

int
nortel_cfg_split_tunnel (struct nortelHandle * h_nortel)
{
   uint32_t gateway_ip = h_nortel->cfg->gatewayIP;
   struct sockaddr_in remote;
   struct sockaddr_in any;
   struct ph1handle * ph1 = NULL;
   char src [NI_MAXHOST], dst [NI_MAXHOST];
   char * policy_in_none = "in none";
   char * policy_out_none = "out none";
   char policy_out[POLICY_STR_LEN], policy_in[POLICY_STR_LEN]; 

   if (nortel_cfg_split_tunnel_mode (h_nortel))
   {
	  plog (LLV_DEBUG, LOCATION, NULL, "Don't need nortel_cf_split_tunnel!\n");
      return 0;
   }
   /* get remote gw into sockaddr */
   memset (&remote, 0, sizeof (remote));
   remote.sin_family = AF_INET;
   remote.sin_addr.s_addr = gateway_ip;
 
   memset (&any, 0, sizeof (any));
   any.sin_family = 2;
 
   memset (dst, 0, sizeof (dst));
   strcpy (dst, sock_numeric_host ((struct sockaddr *)&remote));

   memset (&any, 0, sizeof (any));
   any.sin_family = 2;

   ph1 = nortel_get_ph1_handle (h_nortel);

   if (ph1 == NULL) {
      plog (LLV_ERROR, LOCATION, NULL, "cannot get ph1 handle for remote %s", dst);
      return -1;
   }

   memset (src, 0, sizeof (src));
   strcpy (src, sock_numeric_host (ph1->local));
   
   sprintf(policy_out, "out ipsec esp/tunnel/%s-%s/require", src, dst);
   sprintf(policy_in, "in ipsec esp/tunnel/%s-%s/require", dst, src);

   plog (LLV_INFO, LOCATION, NULL,"Disabling all other routes as split tunelling is not enabled");
 
   /* FIXME: allow all communication to gateway? */
   pfkey_add_policy_to_SPD ((struct sockaddr *) &any,
                            0, 
                            (struct sockaddr *) &remote,
                            32, /* not a network */
                            0,
                            ipsec_set_policy (policy_in_none, strlen (policy_in_none)),
                            ipsec_set_policy (policy_out_none, strlen (policy_out_none)),
                            0);

   /* discard any <-> any */
   /*
   pfkey_add_policy_to_SPD ((struct sockaddr *) &any,
                            0,
                            (struct sockaddr *) &any,
                            0,
                            0,
                            ipsec_set_policy (policy_in_discard, strlen (policy_in_discard)),
                            ipsec_set_policy (policy_out_discard, strlen (policy_out_discard)),
                            0);
   */

   /* tunnel everything */
   pfkey_add_policy_to_SPD ((struct sockaddr *) &any,
                            0,
                            (struct sockaddr *) &any,
                            0,
                            0,
                            ipsec_set_policy (policy_in, strlen (policy_in)),
                            ipsec_set_policy (policy_out, strlen (policy_out)),
                            0);


   return 0;
}  


struct isakmp_data *
nortel_cfg_set (struct nortelHandle * h_nortel, 
                struct isakmp_data *attr)
{
   switch (ntohs (attr->type) & ~ISAKMP_GEN_MASK){
      case CFG_NAT_KEEPALIVE_INTERVAL:
         return nortel_cfg_set_nat_keepalive (h_nortel, attr);
         break;
   }
   plog (LLV_INFO, LOCATION, NULL, "Invalid Attribute %x\n", ntohs (attr->type));
   return NULL;
}

static struct isakmp_data *
nortel_cfg_set_nat_keepalive (struct nortelHandle * h_nortel,
                              struct isakmp_data *attr)
{
   struct isakmp_data *reply = NULL;
   struct isakmp_data *resp = NULL;
   struct ph1natt_options *natt = NULL;
   vchar_t *buffer = NULL;

   plog (LLV_INFO, LOCATION, NULL,
         "received CFG_NAT_KEEPALIVE_INTERVAL");
   
   resp = (struct isakmp_data *)malloc(sizeof(struct isakmp_data) + sizeof(struct ph1natt_options));

   if (! resp) {
      plog(LLV_ERROR, LOCATION, NULL,
           "Cannot allocate memory\n");
      return NULL;
   }
   
   resp->type = PRIVATE_NATTVID_PAYLOAD_TYPE;
   resp->lorv = sizeof(struct ph1natt_options);
   natt = (struct ph1natt_options *) (resp + 1);
   
   memset(natt, 0, sizeof(struct ph1natt_options));
   natt->version = NATT_VERSION_VENDOR_SPECIFIC;
   natt->float_port = 4500;
   natt->encaps_type = UDP_ENCAP_ESPINUDP;

   nortel_nat_enable_natt (h_nortel, resp);

   free (resp);

   if ((buffer = vmalloc(sizeof(*attr))) == NULL) {
      plog(LLV_ERROR, LOCATION, NULL,
           "Cannot allocate memory\n");
      return NULL;
   }

   reply = (struct isakmp_data *) buffer->v;
   reply->type = htons(attr->type | ISAKMP_GEN_TV);
   reply->lorv = htons(0);
      
   return reply;
}
