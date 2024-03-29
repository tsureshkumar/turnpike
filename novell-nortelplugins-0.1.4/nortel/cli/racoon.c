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
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/queue.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/stat.h>

/* turnpike fx headers */
#ifdef HAVE_TURNPIKE_DIR
#include "racoonconf.h"
#else
#include "turnpike/racoonconf.h"
#endif

#include "nortelcli.h"
#include "phase1.h"
#include "phase2.h"
#include "helper.h"
#include "common/helper.h"




int nortel_write_racoon_conf_for_reparse(struct racoon_conf *rcbuf, void *gp)
{
	FILE *fp = NULL;
	struct pluginInfo *pInfo = (struct pluginInfo *)gp;
	struct in_addr temp_addr;
	char racoon_conf_file[512]; //Enough?
	
	
	strcpy(racoon_conf_file, (const char *) getUserHome());
	strcat(racoon_conf_file, RACOON_CONF_FILE1);
	
	umask(006);
	fp = fopen(racoon_conf_file, "w+");
	if(fp == NULL)
	{
		printf("Could not open file\n");
		return -1;
	}
	fprintf(fp, "# racoon.conf generated by Turnpike\n");
	fprintf(fp, "path include \"/etc/racoon\";  \n");
	fprintf(fp, "include \"racoon.conf\";  \n");
	
	if(pInfo->ifInfo.authentication_type == CERTIFICATE)
	{
	        fprintf(fp, "path certificate \"%s/.turnpike\";\n",getUserHome());
	}
	
		
	temp_addr.s_addr = pInfo->ifInfo.server_ip_addr;
//	fprintf(fp, "remote %s inherit anonymous\n", inet_ntoa(temp_addr));
	fprintf(fp, "remote %s\n", inet_ntoa(temp_addr));
	fprintf(fp, "{\n");
	fprintf(fp, "	nat_traversal on;\n");
	if (pInfo->ifInfo.withProfileFile)
		fprintf(fp, "	exchange_mode %s;	\n", ph1get_modestr(rcbuf->ph1Config.entry_mode));
	else
	{
		if(pInfo->ifInfo.authentication_type == CERTIFICATE)
			fprintf(fp, "	exchange_mode main;	\n");
		else if(pInfo->ifInfo.authentication_type == XAUTH)
			fprintf(fp, "   exchange_mode aggressive;	\n");
	}
	fprintf(fp, "	doi ipsec_doi;\n	\
situation identity_only;\n	\
verify_cert off;\n	");

	if(pInfo->ifInfo.authentication_type == XAUTH)
	{
		fprintf(fp, "my_identifier keyid;\n	");
	}
	else if(pInfo->ifInfo.authentication_type == CERTIFICATE)
	{
		fprintf(fp, "my_identifier asn1dn;\n	");
		fprintf(fp, "certificate_type x509 \"usercert.pem\" \"userkeyunenc.pem\";\n	");
	}

	fprintf(fp, "nonce_size 16;\n	\
initial_contact on;\n	\
proposal_check obey;	\n\n");

	//Write the ph1 multiple proposal with requested dh group 

       if(pInfo->ifInfo.withProfileFile)
               write_PH1_proposal(fp,rcbuf->ph1Config.dh_group, pInfo->ifInfo.authentication_type);
       else
               write_PH1_proposal(fp,pInfo->ifInfo.dh_group, pInfo->ifInfo.authentication_type);

/*
 * Multiple Proposal Changes : Preggna
 *
 * Commenting the phase 1 details written from 
 * profile file as multiple proposal is being
 * tried out
 */

/*
	//Phase1 details
	fprintf(fp, "	proposal {\n");
	fprintf(fp, "		encryption_algorithm %s;\n",ph1get_encalgo(rcbuf->ph1Config.encryption_algo));
	fprintf(fp, "		hash_algorithm %s;\n", ph1get_hashalgo(rcbuf->ph1Config.hash_algo));
	fprintf(fp, "		authentication_method %s;\n", ph1get_authmethod(rcbuf->ph1Config.auth_method));
	fprintf(fp, "		dh_group %s;\n",ph1get_dhtype(rcbuf->ph1Config.dh_group));
	fprintf(fp, "	}\n");
*/
	fprintf(fp, "}\n");

	//Phase2 details
	temp_addr.s_addr = pInfo->ifInfo.source_ip_addr;
	fprintf(fp, "sainfo address %s/%d[0] any address 0.0.0.0-255.255.255.255[0] any\n",inet_ntoa(temp_addr), 32);
	fprintf(fp, "{\n");
	if (pInfo->ifInfo.withProfileFile)
	{
	/*	fprintf(fp, "	pfs_group %s;\n", ph2get_pfsgroup(rcbuf->ph2Config.pfs_group));
		fprintf(fp, "	encryption_algorithm %s;\n",
			ph2get_enctype(rcbuf->ph2Config.encryption_algorithm));
		fprintf(fp, "	authentication_algorithm %s;\n",
			ph2get_authmethod(rcbuf->ph2Config.authentication_algorithm));
		fprintf(fp, "	compression_algorithm deflate;\n");*/
		write_PH2_proposal(fp, rcbuf->ph2Config.pfs_group);
	}
	else
	{
		//Phase2 to have multiple proposals
		write_PH2_proposal(fp, pInfo->ifInfo.pfs_group);
		/*
		fprintf(fp, "	pfs_group 1;\n");
		fprintf(fp, "	encryption_algorithm des;\n");
		fprintf(fp, "	authentication_algorithm hmac_md5;\n");
		fprintf(fp, "	compression_algorithm deflate;\n");
		*/
	}
	fprintf(fp, "}\n");
		
		
	temp_addr.s_addr = pInfo->ifInfo.source_ip_addr;
	fprintf(fp, "sainfo address 0.0.0.0-255.255.255.255[0] any address %s/%d[0]"
			" any\n", inet_ntoa(temp_addr), 32);
	fprintf(fp, "{\n");
	if (pInfo->ifInfo.withProfileFile)
	{
	/*	fprintf(fp, "	pfs_group %s;\n", ph2get_pfsgroup(rcbuf->ph2Config.pfs_group));
		fprintf(fp, "	encryption_algorithm %s;\n",
			ph2get_enctype(rcbuf->ph2Config.encryption_algorithm));
		fprintf(fp, "	authentication_algorithm %s;\n",
			ph2get_authmethod(rcbuf->ph2Config.authentication_algorithm));
		fprintf(fp, "	compression_algorithm deflate;\n");*/
		write_PH2_proposal(fp, rcbuf->ph2Config.pfs_group);
	}
	else
	{
		//Phase2 to have multiple proposals
		write_PH2_proposal(fp, pInfo->ifInfo.pfs_group);
		/*
		fprintf(fp, "	pfs_group 1;\n");
		fprintf(fp, "	encryption_algorithm 3des;\n");
		fprintf(fp, "	authentication_algorithm hmac_md5;\n");
		fprintf(fp, "	compression_algorithm deflate;\n");
		*/
	}
	fprintf(fp, "}\n");

	fprintf(fp, "\n");
	fprintf(fp, "\n");
	
	fclose(fp);
	return 0;
}
