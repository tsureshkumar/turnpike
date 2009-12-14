
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
#include <errno.h>
#include <sys/types.h>
#include<sys/stat.h>
#include <stdlib.h>
//#include "vpncError.h"

static int isFileExist(char *string)
{
	struct stat buf;

	if(lstat(string,&buf)<0) {
		return -1;
	}
	else if(!S_ISREG(buf.st_mode) || (buf.st_size==0)) {
		//printf("file size zero\n");
		return -1;
	}
	return 0;
}

#if 0
int getip( const char *destip, char *srcip, char *srcif, char *errstring){

	char *tmpfile=".tmp",*tmperrfile=".tmperr";
	
	if(isFileExist("/sbin/ip")!=0){
		return -1;
	}
	
	
	if((fork())==0){//child
		int fd=creat(tmpfile,S_IRWXU);
		dup2(fd,fileno(stdout));	
		int errfd=creat(tmperrfile,S_IRWXU);
		dup2(errfd,fileno(stderr));	
		execl("/sbin/ip","ip","route","get",destip, NULL);
		close(fd);
		close(errfd);
	}
	else{
		int status;
		wait(&status);
	}

	if(isFileExist(tmperrfile)==0){ //file exusts => error 
		FILE *fp=fopen(tmperrfile,"r");
		if(fp==NULL){
			remove(tmpfile);
			remove(tmperrfile);
			return -1;
		}
		fscanf(fp,"%[^\n]",errstring);
		fclose(fp);	
		remove(tmpfile);
		remove(tmperrfile);
		return -2;
		//return VPNC_ERR_GUICLI_IPADDRESS_NOTRESOLVED;
	}

	char temp[20];
	int i;

	FILE *fp=fopen(".tmp","r");
	if(fp==NULL){
		remove(tmpfile);
		remove(tmperrfile);
		return -1;
	}

	
	for(i=0 ; ;i++){	
		
		if(fscanf(fp,"%s ",temp)!=1)
			break;
		if(strcmp(temp,"dev")==0){
			fscanf(fp,"%s ",temp);
			i++;
			strcpy(srcif,temp);
		}
		if(strcmp(temp,"src")==0){
			fscanf(fp,"%s ",temp);
			i++;
			strcpy(srcip,temp);
		}
			
	}
	
	fclose(fp);		

	remove(tmpfile);
	remove(tmperrfile);
	return 0;
}
#endif

