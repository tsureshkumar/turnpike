
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


#ifndef __TURNPIKE_RACOONCONF_H__
#define __TURNPIKE_RACOONCONF_H__   
 
 /*
  * Following structure has all the info needed for writing racoon conf file
  */

#define RACOON_CERT_PATH "/etc/racoon/racoon.conf"

/* This should come from the base CLI? */
#define TURNPIKE_DIR "/.turnpike/" 
#define RACOON_CONF_FILE1 TURNPIKE_DIR"racoon.conf"

 struct ph1_config{
        u_int8_t        encryption_algo;
        u_int8_t        hash_algo;
        u_int8_t        auth_method;
        u_int8_t        dh_group;
	u_int32_t		entry_mode;
  };


  struct ph2_config{
        u_int8_t        pfs_group;
        u_int8_t        encryption_algorithm;
        u_int8_t        authentication_algorithm;
        u_int8_t        compression_algorithm;
        u_int32_t       lifetime;
  };


  struct racoon_conf{
        struct ph1_config ph1Config;
        struct ph2_config ph2Config;
	u_int32_t num_networks;
	char networks[1]; /* Format : list of entry network followed by mask as
u_int32_t's */
  };
#endif
