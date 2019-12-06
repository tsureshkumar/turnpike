
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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif // HAVE_CONFIG_H
#include <string.h>
#include <signal.h>
#include <stdlib.h>
#include "CommonUI.h"
#include "commandHandler.h"
#include "vpncErrorHandling.h"
#include "cliErrors.h"
extern Inf_t Inf;
extern char* errString(int, char*);
extern int displayProfileList(void);
extern void usage(void);
extern int connectHandler();
extern int getVendorProfileName(char *file);
extern int isProfileExist(char *file);
extern int disconnectHandler(int);
extern int loadmodule(const char *file_name);
extern int getGatewayType(char *file);

static int listHandler(void)
{
	if(setUserEnv(&Inf)<0)
	{
        	fprintf (stderr, errString (CAN_NOT_SET_USR_ENV,Inf.errStr));
		return -1;
	}
	if(displayProfileList()<0)
        return -1;
        
    return 0;
}

static int helpHandler(void)
{
    usage();
    exit(0);
}

/*
 *  This function is meant for creating vendor specific profiles.
 *  It is expected that the vendor registered will provide a handler to do this.
 */
static int create_vendor_profile()
{
    int c = 0;
    char lib_path_name[MAX_PATH_LEN] = {'\0'};
    int with_profile_file = 0;
    char vendor_file_path_name[MAX_PATH_LEN] = {'\0'};
	int ret = 0;

    /* Check if the given profile file exist */
    if(isProfileExist(Inf.profileName)<0)
    {
       // fprintf (stderr, errString (PROFILE_FILE_DOES_NOT_EXIST,Inf.errStr),Inf.profileName);
	printf("The corresponding profile file for was not found.\n");
	while(1)
	{
		printf("Do you want to create an independent vendor profile ? [y/n] ");
		if( (c = getchar()) == 'n')
		{
			return 0;
		}
		else if(c == 'y')
		{
			break;
		}
		else
		{
			printf("Invalid option\n");
		}
	}
	printf("Please enter gateway type\n");
	ret = scanf("%s", Inf.gatewayType);
	if (ret != 1)
		fprintf (stderr, "scanf failed.\n");

	getchar();
	with_profile_file = 0;
	if(setUserEnv(&Inf)<0)
	{
        	fprintf (stderr, errString (CAN_NOT_SET_USR_ENV,errStr));
        	return -1;
    	}
    }
    /* Get the gateway type from the profile file */
   else
   {
	 if(getGatewayType(Inf.profileName)<0)
    	 {
        	fprintf (stderr, errString (BAD_PROFILE,Inf.errStr),Inf.profileName);
        	exit(1);
	 }
	 with_profile_file = 1;
   }

    if(Inf.isStandardGateway)
        printf(_("This functionality is available only for vendors that provide this support\n"));
    else
    {
        /* Load the vendor plugin */
       	sprintf(lib_path_name,
	        	LIB_LOAD_PATH"/libcli%s.so",Inf.gatewayType);
    	printf(_("Loading module : %s\n"),lib_path_name);
        if(loadmodule(lib_path_name) < 0)
	{
		return -1;
	}

        /* Call the plugin handler to create the vendor profile */
	strcpy(vendor_file_path_name, Inf.userHome);
	strcat(vendor_file_path_name, VENDOR_PROFILE_PATH1 );
	
	if(with_profile_file)
	    getVendorProfileName(Inf.profileName);
	else
	{
		int i = 0, j = 0;
		char vendor_file[MAX_PATH_LEN] = {'\0'};
		while( (Inf.profileName[i] != '\0') && (Inf.profileName[i] != '_'))
		{
			i++;
		}
		i++;
		while(Inf.profileName[i] != '\0')
		{
			if(Inf.profileName[i] == '.')
			{
				break;
			}
			vendor_file[j++] = Inf.profileName[i++];
		}
		strcat(Inf.vendorfile, "vendor_");
		strcat(Inf.vendorfile, vendor_file);
		strcat(Inf.vendorfile, ".prf");
	}
	
	strcat(vendor_file_path_name, Inf.vendorfile);
	strcpy(Inf.vendorfile, vendor_file_path_name);

        if (Inf.plugin_create_vendor_profile)
	       	Inf.plugin_create_vendor_profile(Inf.vendorfile);
        else
            printf(_("Vendor %s does not provide functionality for creating vendor profiles!\n"),
                Inf.gatewayType);
    }            
    return 0; 
}

int commandHandler()
{
    

    /* TODO : Change this switch to "set bit test" when more than one option is allowed */

    switch(Inf.argumentMask)
    {
        case LIST:
            if(listHandler()<0)
                return -1;
            break;

	case CONNECT:
        case CONNECT | DHGROUP:
	case CONNECT | PFSGROUP:
	case CONNECT | DHGROUP | PFSGROUP:
	case CONNECT | DHGROUP | PFSGROUP | UPSCRIPT:
            if(connectHandler()<0)
                return -1;
            break;

        case DISCONNECT:
            if(disconnectHandler(0)<0) 
                return -1;
            break;

        case HELP:
            if(helpHandler()<0)
                return -1;
            break;
        case CREATE_VENDOR_PROFILE:
            if (create_vendor_profile()<0)
                return -1;
        default:
            // Wouldnt reach here 
            break;

    }
    return 0;
}

