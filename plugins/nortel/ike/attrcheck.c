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

#include "nortel_vmbuf.h"
#include "nortel_inf.h"

/* Racoon Headers */
#include "racoon/isakmp_var.h"
#include "racoon/isakmp.h"
//#include "plog.h"

int nat_dst_float_port = 4500;

int setNATFloatingPort(struct isakmp_data *data)
{
   int type = 0, retval = 0;
   //u_int16_t lorv;
  
   if(data == NULL)
   {
	return -1;
   }
        
   type = ntohs(data->type) & ~ISAKMP_GEN_MASK;
   //lorv = ntohs(data->lorv);

   switch(type) {
	case UDP_ENCAP_FLAG:
		nat_dst_float_port = data->lorv;
   		break; 
	default:
		
	    //plog(LLV_ERROR, LOCATION, NULL, "Unknown ipsec attrib type: %d\n", type);
	    retval = -1; 
   }

   return retval;
}

int checkXtenddClientVer(struct isakmp_data *data)  
{

   int type = 0, retval = 0;
  
   if(data == NULL)
   {
	return -1;
   }
        
   type = ntohs(data->type) & ~ISAKMP_GEN_MASK;

   switch(type) {
	case XTNDD_CONTIVITY_CLIENT_VERSION:	 
   		break; 
	default:
	    retval = -1; 
   }

   return retval;
}
