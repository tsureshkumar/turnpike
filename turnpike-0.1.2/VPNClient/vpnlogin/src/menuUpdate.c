
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
#include<sys/stat.h>
#include <string.h>
#include <libxml/xmlmemory.h>
#include <libxml/parser.h>
#include <libxml/tree.h>

#define CONFIG_PATH "/etc/"
#define XMLFILE CONFIG_PATH"gnome/gnome-vfs-2.0/vfolders/applications-all-users.vfolder-info"
#define DESKTOPFILE CONFIG_PATH"gnome/gnome-vfs-2.0/vfolders/applications-all-users/vpnlogin.desktop"

#define INSTALL 1
#define UNINSTALL 2

int main(int argc, char **argv)
{

	xmlNode *cur_node, *child_node, *folder_node = NULL, *vpn_node = NULL;
	xmlChar *buffer;
	xmlDocPtr doc;
	int mode = -1;

	
	struct stat buf;
		
	if(lstat(XMLFILE,&buf)<0) {
	return 0;
	}
	else if(!S_ISREG(buf.st_mode) || (buf.st_size==0)) {
		return 0;
	}


	if(argc > 1)
	{
		if(strcmp(argv[1], "-i") == 0)
		{
			mode = INSTALL;
		}
		else
		if(strcmp(argv[1], "-u") == 0)
		{
			mode = UNINSTALL;
		}
		else
			return -1;

	}
	else
		return -1;

	
	doc = xmlParseFile(XMLFILE);
	if (doc == NULL) 
	{
		return -1;
	}

	/*Get the root element node */
	xmlNode *root = NULL;
	root = xmlDocGetRootElement(doc);
	if( !root || !root->name ||xmlStrcmp(root->name,(const xmlChar *)"VFolderInfo")) { 
	xmlFreeDoc(doc);
	return -1;
	}

	//Find the name
	for(cur_node = root->children; cur_node != NULL; cur_node = cur_node->next) 
	{
		if ( cur_node->type == XML_ELEMENT_NODE  && !xmlStrcmp(cur_node->name, (const xmlChar *) "Folder"))
		{  
			folder_node = cur_node;
			break;
                }
	}
	if(folder_node)
	{
		for(cur_node = folder_node->children; cur_node != NULL; cur_node = cur_node->next)
		{
			if ( cur_node->type == XML_ELEMENT_NODE  && !xmlStrcmp(cur_node->name, (const xmlChar *) "Desktop"))
			{  
				vpn_node = cur_node;
				break;
       		         }
		}
	}
	//Check if the entry is already present
	if(mode == INSTALL)
	{
		if(vpn_node)
		{
			for(cur_node = folder_node->children; cur_node != NULL; cur_node = cur_node->next)
			{
				if ( cur_node->type == XML_ELEMENT_NODE  && !xmlStrcmp(cur_node->name, (const xmlChar *) "Include"))
				{  
					buffer = xmlNodeGetContent(cur_node);
					if(strcmp((const char*)buffer, DESKTOPFILE) == 0)
					{
						xmlFree(buffer);
						xmlFreeDoc(doc);
						return -1;
					}
				}
			}
			child_node=xmlNewTextChild(folder_node,NULL,(const xmlChar *)"Include",(const xmlChar *)DESKTOPFILE);
			xmlKeepBlanksDefault(0);
			xmlSaveFormatFile(XMLFILE,doc,1);

		}

	}
	else if(mode == UNINSTALL)
	{
	if(vpn_node)
		{
			for(cur_node = folder_node->children; cur_node != NULL; cur_node = cur_node->next)
			{
				if ( cur_node->type == XML_ELEMENT_NODE  && !xmlStrcmp(cur_node->name, (const xmlChar *) "Include"))
				{  
					buffer = xmlNodeGetContent(cur_node);
					if(strcmp((const char *)buffer, DESKTOPFILE) == 0)
					{
						xmlFree(buffer);
						xmlUnlinkNode(cur_node);
						xmlFreeNode(cur_node);
						xmlKeepBlanksDefault(0);
						xmlSaveFormatFile(XMLFILE,doc,1);
						xmlFreeDoc(doc);
						return 0;
					}
				}
			}

		}
	}

	xmlFreeDoc(doc);

	return 0;
}
