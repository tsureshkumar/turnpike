
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
#include <stdlib.h>
#include <unistd.h>
#include <getopt.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pwd.h>
#include <string.h>

/* cli headers */
#include "commoncli.h"
#include "vpncErrorHandling.h"
#include "cliErrors.h"
#include "CommonUI.h"
#include "utility.h"

/* Racoon headers */
#include "racoon/admin.h"

/* globals */
Inf_t Inf;
extern char PLOG_FILE[];
extern char* errString(int, char*);
extern int commandHandler();
void get_routes(const char* optarg);

static int parseArguments(int argc,char **argv) 
{
	int c = 0;
	int optionIndex = 0;
	static struct option long_options[] =
	{
		{"connect", 	1, 0, CONNECT},
		{"disconnect",	0, 0, DISCONNECT},
		{"list",	0, 0, LIST},
		{"help",	0, 0, HELP},
		{"verbose", 	0, 0, VERBOSE},
		{"routes", 	0, 0, ROUTES},
		{"create_vendor_profile",    1,  0,  CREATE_VENDOR_PROFILE},
		{"dhgroup",	1,	0,	DHGROUP},
		{"pfsgroup",	1,	0,	PFSGROUP},
		{"nosplittunnel",	0,	0,	NOSPLITTUNNEL},
		{"up", 1, 0, UPSCRIPT},
		{0, 		0, 0, 0}
	};

	Inf.argumentMask = 0;
	Inf.isVerbose = 0;

	while(1)
	{
		c = getopt_long(argc, argv,"c:p:g:u:r:s:tdlhv",
				long_options, &optionIndex);

		if (c == -1)
			break;

		switch(c)
		{
			case 'c':
			case CONNECT:
			/*	
				if((Inf.argumentMask) && (!Inf.isVerbose))
				{
					fprintf (stderr, errString (TOO_MANY_ARGUMENTS,Inf.errStr));
					exit(1);
				}
				if (Inf.isVerbose)
				{
					if (argc > 4 )
					{
						fprintf (stderr, errString (TOO_MANY_ARGUMENTS,Inf.errStr));
						syntax();
						break;				
					}
				}
			*/
				memset(Inf.profileName, 0, MAX_STRING_LEN);

				/* Check if this is a profile name or stdin */
				if (!strcmp(optarg,"-")) //if stdin just copy
				{
					strcpy(Inf.profileName,optarg);
					Inf.withProfileFile=0;
				}	
				else
				{
					//if profile name store the file name instead
					strcpy(Inf.profileName,"profile_");
					strcat(Inf.profileName , optarg);
					strcat(Inf.profileName, ".prf");

					Inf.withProfileFile=1;
				}
				Inf.argumentMask|=CONNECT;
				break;
			case 'u' :
			case UPSCRIPT:
				memset(Inf.upscript, 0, MAX_PATH_LEN);
				strcpy(Inf.upscript, optarg);
				Inf.argumentMask |= UPSCRIPT;
				printf("upscript name : %s\n", Inf.upscript);
				break;

			case 'p':
			case CREATE_VENDOR_PROFILE:

				if(Inf.argumentMask)
				{
					fprintf(stderr, errString(TOO_MANY_ARGUMENTS,Inf.errStr));
					exit(1);
				}
				if(argc > 3)
				{
					fprintf (stderr, errString(TOO_MANY_ARGUMENTS,Inf.errStr));
					syntax();
					break;
				}
				memset(Inf.profileName, 0, MAX_STRING_LEN);

				//Store the file name instead of profile name
				strcpy(Inf.profileName,"profile_");
				strcat(Inf.profileName , optarg);
				strcat(Inf.profileName, ".prf");
				/*
				   memset(Inf.vendorName, 0, MAX_STRING_LEN);
				   strcpy(Inf.vendorName , optarg);
				   */
				Inf.argumentMask|=CREATE_VENDOR_PROFILE;
				break;


			case 'g':
			case DHGROUP:
				Inf.dh_group = atoi(optarg);
				if(! ((Inf.dh_group == 1)||(Inf.dh_group == 2)))
				{
					printf("Only dh1 and dh2 are supported\n");
					return -1;	
				}
				Inf.argumentMask |= DHGROUP;
				break;
			case 's':
			case PFSGROUP:
				Inf.pfs_group = atoi(optarg);
				if(! ((Inf.pfs_group == 1)||(Inf.pfs_group == 2)||(Inf.pfs_group == 0)))
				{
					printf("Only pfsgroup 1 and 2 are supported\n");
					return -1;	
				}
				Inf.argumentMask |= PFSGROUP;
				break;

			case 'd':
			case DISCONNECT:

				if(Inf.argumentMask)
				{
					fprintf (stderr, errString(TOO_MANY_ARGUMENTS,Inf.errStr));
					exit(1);
				}

				if(argc > 2)
				{
					fprintf (stderr, errString(TOO_MANY_ARGUMENTS,Inf.errStr));
					syntax();
					break;
				}
				Inf.argumentMask|=DISCONNECT;
				Inf.withProfileFile = 1;
				break;
			case 'r':
			case ROUTES:
				get_routes(optarg);
				break;
			case 'l':
			case LIST:
				if(Inf.argumentMask)
				{
					fprintf (stderr, errString(TOO_MANY_ARGUMENTS,Inf.errStr));
					exit(1);
				}

				if(argc > 2)
				{
					fprintf (stderr, errString(TOO_MANY_ARGUMENTS,Inf.errStr));
					syntax();
					break;
				}
				Inf.argumentMask|=LIST;
				break;

			case 't':
			case NOSPLITTUNNEL:
				Inf.no_split_tunnel = 1;
				break;

			case 'h':
			case HELP:
				if(Inf.argumentMask)
				{
					fprintf (stderr, errString(TOO_MANY_ARGUMENTS,Inf.errStr));
					exit(1);
				}
				Inf.argumentMask|=HELP;
				break;


			case 'v':
			case VERBOSE:
				//	Inf.argumentMask |= VERBOSE;
				Inf.isVerbose = 1;
				break;

			case '?':
				syntax();
				opterr = 0;
				break;

			default:
				abort();
				break;
		}
	}
	if( (Inf.isVerbose) && (Inf.argumentMask == 0))
	{
		usage();
		opterr = 0;
		return -1;
	}

	if(commandHandler()<0)
		return -1;

	return 0;
}

void object_set_up()
{
	char userHome[MAX_STRING_LEN] = { '\0' };
	struct passwd *pw;
	if (!(pw = getpwuid(getuid())))
		return ;
	strcpy(userHome, pw->pw_dir);
	strcpy(PLOG_FILE, userHome);
	strcat(PLOG_FILE, PLOG_FILE1); // Generate the log file at /~/.turnpike/log.txt

	Inf.get_connect_client_sock = get_connect_client_sock;
	Inf.get_connect_client_event_poll_sock = get_connect_client_event_poll_sock;
	Inf.print_event = print_evt;
	Inf.connecting_time_update = NULL;
	Inf.conection_status_update = NULL;
	Inf.on_vpnlogin_destroy_mainWindow = NULL;
	Inf.printing_function = printing_function;
	Inf.updateUptime = NULL;
	Inf.refresh = NULL;
	Inf.connInProgress = FALSE;
	Inf.runEventPoll = 1;
	Inf.connected = 0;
	Inf.mainWindowActive = FALSE;
	Inf.keepMainWindow = 0;
	Inf.pluginBufLen = 0;
	Inf.network_mask_list = NULL;
	Inf.dh_group = -1;
	Inf.pfs_group = -1;
	//if(pw)
	//{
	//      free(pw->pw_name);       /* user name */
	//      free(pw->pw_passwd);     /* user password */
	//      free(pw->pw_gecos);      /* real name */
	//      free(pw->pw_dir);        /* home directory */
	//      free(pw->pw_shell);      /* shell program */
	//      free(pw);
	//}
}


int  main(int argc,char **argv)
{      
	object_set_up();
	plogset(PLOG_FILE);
	ploginit();
	plog(LLV_INFO, NULL, NULL, "Novell VPN Client for Linux CLI Startup ....\n");
#ifdef __DEBUG__
	printf(_("Launching CLI with uid = %d\n"),getuid());
#endif
	if(argc == 1)
	{
		syntax();
		printLine();
		return -1;
	}

	if(parseArguments(argc,argv)<0)
	{
		return -1;
	}

	return 0;
}

void get_routes(const char* optarg)
{
	int i = 0;
	struct Routes* trav ;
	int optarg_pointer = 0;

	trav = Inf.network_mask_list;

	for( ; optarg[optarg_pointer] != '\0';)
	{
		char net_mask_str[30] = {'\0'};
		int j = 0;
		if(trav == NULL)
		{
			trav = (struct Routes *) malloc( sizeof(struct Routes));
			Inf.network_mask_list = trav;
		}
		else
		{
			trav->next = (struct Routes *) malloc( sizeof(struct Routes));
			trav = trav->next;
		}
		while( (optarg[ optarg_pointer ] != ' ') && (optarg[ optarg_pointer ] != '\0'))
		{
			net_mask_str[j++] = optarg[optarg_pointer++];
		}
		i = 0;
		while(net_mask_str[i] != '.'){i++;}
		while(net_mask_str[i] != '.'){i++;}
		while(net_mask_str[i] != '.'){i++;}
		while(net_mask_str[i] != '/'){i++;}

		strncpy(trav->network, net_mask_str, i );
		trav->network[i] = '\0';

		i++;
		strcpy(trav->mask, &(net_mask_str[i]));
		trav->mask[strlen(net_mask_str)-i] = '\0';

		trav->next = NULL;
		if(optarg[optarg_pointer] == ' ')
			optarg_pointer++;
	}	
}	


