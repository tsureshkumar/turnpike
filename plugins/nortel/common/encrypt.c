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

#include "encrypt.h"

#define STRIVEC "QWERTGBVCXZA"

static int nortel_encrypt (char *clearText,int len,char *cipherText,char *inkey,int keylen);
static int nortel_decrypt (char *cipherText,int len,char *decryptText,char *inkey,int keylen);


//#define __DEBUG__ 1

static int
nortel_encrypt (char *clearText,int len,char *cipherText,char *inkey,int keylen)
{
	
	DES_key_schedule sched;
	
	DES_cblock key,ivec;
	memset(&key,0,sizeof(key));
	DES_string_to_key(inkey,&key);
	
#if __DEBUG__ ==1

	printf("\nGenerated Key \n");
	for(i=0;i<sizeof(key);i++)
		printf("%x ",key[i]);	
	
	printf("\nSet odd parity Key \n");
#endif	
	DES_set_odd_parity(&key);
#if __DEBUG__ ==1
	for(i=0;i<sizeof(key);i++)
		printf("%x ",key[i]);	
	
	printf("\nsizeof sched %d\n", sizeof(sched));
#endif	
	
	memset(&sched,0,sizeof(sched));
	DES_set_key_checked(&key,&sched);
	
#if __DEBUG__ ==1
	printf("\nSchedule is \n");
	for(i=0;i<sizeof(sched);i++)
		printf("%x ",*((char *)(&sched)+i));	
	
	printf("\n");
	
	printf("sizeof ivec %d\n", sizeof(ivec));
#endif	
	
	memset(&ivec,0,sizeof(ivec));
	DES_string_to_key(STRIVEC,&ivec);
	 	
#if __DEBUG__ ==1
	printf("\nGenerated Ivec \n");
	for(i=0;i<sizeof(ivec);i++)
		printf("%x ",ivec[i]);	
	printf("\n");
#endif	

		
	DES_ncbc_encrypt ((const unsigned char *) clearText,
			  (unsigned char *) cipherText,
			  len,
			  &sched,
			  &ivec,
			  DES_ENCRYPT); // 1 is encrypt

#if __DEBUG__ ==1
	printf("\nGenerated Cipher \n");
	for(i=0;i<len;i++)
		printf("%x ",cipherText[i]);	
	printf("\n");

#endif	
	return 0;
}

static int 
nortel_decrypt (char *cipherText,int len,char *decryptText,char *inkey,int keylen)
{
	DES_key_schedule sched;

	DES_cblock key,ivec;
//	memcpy(key,KEY,sizeof(KEY));
//	memcpy(ivec,IVEC,sizeof(IVEC));
	
#if __DEBUG__ ==1
	printf("sizeof key %d\n", sizeof(key));
#endif	
	memset(&key,0,sizeof(key));
	DES_string_to_key(inkey,&key);
	 	
#if __DEBUG__ ==1
	printf("\nGenerated Key \n");
	for(i=0;i<sizeof(key);i++)
		printf("%x ",key[i]);	

	printf("\nSet odd parity Key \n");
#endif	
	DES_set_odd_parity(&key);
#if __DEBUG__ ==1
	for(i=0;i<sizeof(key);i++)
		printf("%x ",key[i]);	

	printf("\nsizeof sched %d\n", sizeof(sched));

#endif	
	memset(&sched,0,sizeof(sched));
	DES_set_key_checked(&key,&sched);

#if __DEBUG__ ==1
	printf("\nSchedule is \n");
	for(i=0;i<sizeof(sched);i++)
		printf("%x ",*((char *)(&sched)+i));	

	printf("\n");

	printf("sizeof ivec %d\n", sizeof(ivec));
#endif	
	memset(&ivec,0,sizeof(ivec));
	DES_string_to_key(STRIVEC,&ivec);
	 	
#if __DEBUG__ ==1
	printf("\nGenerated Ivec \n");
	for(i=0;i<sizeof(ivec);i++)
		printf("%x ",ivec[i]);	
	printf("\n");
#endif	

//	if(len%8!=0)
//		len+=(8-len%8);
	DES_ncbc_encrypt( (const unsigned char *) cipherText,
			  (unsigned char *) decryptText,
			  len,
			  &sched,&ivec,DES_DECRYPT); // 1 is encrypt

#if __DEBUG__ ==1
	printf("\nDecrypted ClearText \n");
	for(i=0;i<len;i++)
		printf("%x(%c) ",decryptText[i],decryptText[i]);	
	printf("\n");
#endif	

	return 0;	
}

// passwd length max is 256. I use 1024 buffers to have enough room!
int
nortel_encode(const char *clear, int clearlen, char *encode, int *encodelen,char *key, int keylen){

	unsigned char cipherText[1024]={0};
	int rem;	
	unsigned char clearText[1024];
	memcpy(clearText,clear,clearlen);
	int i;	

	if (!clearlen) {
	    *encodelen = 0;
	    encode[*encodelen]='\0';
	}
	if((rem=clearlen%8)!=0){
		for(i=clearlen;i<clearlen+(8-rem);i++)
			clearText[i]=' ';
	}
	int roundedLen=clearlen+8-rem;
	nortel_encrypt( (char *) clearText, roundedLen, (char *) cipherText,key,keylen);
	
	char buf[1024];
	memset(buf,0,1024);

	/* Store the original length */
	
	if(clearlen<=15){	
		sprintf(buf,"%c",'0');
		sprintf(buf+1,"%x",(unsigned int) (clearlen));
	}
	else
		sprintf(buf,"%x",clearlen);
				
	/* store the encrypted passwd */
	
	for(i=0;i<roundedLen;i++){
		if(cipherText[i]<=15){
			sprintf(buf+2+i*2,"%c",'0');
			sprintf(buf+2+i*2+1,"%x",cipherText[i]);
		}
		else
			sprintf(buf+2+i*2,"%x",cipherText[i]);
	}	
	memcpy(encode,buf,roundedLen*2  +2  );//2 is for the len itself
	*encodelen=roundedLen*2  +2  ;
	encode[*encodelen]='\0';
	return 0;
}


int 
nortel_decode (char *cipher, int cipherlen, char *decode, size_t *decodelen,char *key, int keylen)
{
	char lookup[128];
	unsigned char cipherText[1024];
	unsigned char decryptText[1024];

	if (cipherlen < 2) {
	    *decodelen = 0;
	    decode[0] = '\0';
	    return 0;
	}
	    
	lookup['0']=0x0;
	lookup['1']=0x1;
	lookup['2']=0x2;
	lookup['3']=0x3;
	lookup['4']=0x4;
	lookup['5']=0x5;
	lookup['6']=0x6;
	lookup['7']=0x7;
	lookup['8']=0x8;
	lookup['9']=0x9;
	lookup['a']=0xa;
	lookup['b']=0xb;
	lookup['c']=0xc;
	lookup['d']=0xd;
	lookup['e']=0xe;
	lookup['f']=0xf;

	int i,j;
	int origCipherLen=lookup[ (int) cipher[0]]<<4;
	origCipherLen|=lookup[ (int) cipher[1]];

	if (*decodelen < origCipherLen) {
	    *decodelen = 0;
	    decode[0] = '\0';
	    return 0;
	}

	for(i=2,j=0;i<cipherlen;i+=2,j++){
		cipherText[j]=lookup [ (int) cipher[i]]<<4;
		cipherText[j]|=lookup [ (int) cipher[i+1]];
		//	printf("%x\n",lookup[array[i]]<<4);
		//	printf("%x\n",lookup[array[i+1]]);

	}
	
//	for(i=0;i<cipherText.ulen/2;i++)
//		printf("%x\n",output[i]);

	int roundedLen=j+(8-j %8);
	
	nortel_decrypt((char *) cipherText,roundedLen, (char *) decryptText,key,keylen);
	memcpy(decode,decryptText,origCipherLen /* +2 */ );//2 is for the len itself
	*decodelen=origCipherLen /* +2 */ ;
	decode[*decodelen]='\0';
	return 0;
	
}


#if 0
int main(int argc, char **argv){

	String clearString,encodeString,decodeString;
	clearString.ustr=malloc(atoi(argv[2]));
	memcpy(clearString.ustr,argv[1],atoi(argv[2]));
	clearString.ulen=atoi(argv[2]);	

	encodeString.ustr=malloc(1024);
	nortel_encode(&clearString,&encodeString);
	int i;
	printf("Encoded String \n");
	for(i=0;i<encodeString.ulen;i++)
		printf("%x(%c) ",encodeString.ustr[i],encodeString.ustr[i]);
	printf("\nEndof encoding\n");

	String tempString;
	tempString.ustr=malloc(1024);

	nortel_decode(&encodeString,&tempString);

	memcpy(decodeString.ustr,tempString.ustr,tempString.ulen);
	decodeString.ulen=tempString.ulen;	

	printf("Decoded String \n");
	for(i=0;i<decodeString.ulen;i++)
		printf("%x(%c) ",decodeString.ustr[i],decodeString.ustr[i]);

	printf("\nEndof decoding\n");
	return 0;	

}
#endif

#if 0
int writeXml(char *data);
int readXml();

int main(int argc, char **argv){

	unsigned char cipherText[256]={0};
	int i=0,len;
	char clearText[256]={0};
	char decryptText[256]={0};
	FILE*fp=fopen("passwd","a+");	
	if(argc!=3){
		printf("Invalid number of args\n");
		return -1;
	}	

	len=atoi(argv[2]);
	memcpy(clearText,argv[1],len);

	int rem;	
	if((rem=len%8)!=0){
		for(i=len;i<len+(8-rem);i++)
			clearText[i]=' ';
	}

	nortel_encrypt(clearText,len,cipherText);

	//	fseek(fp,-1,SEEK_CUR);	
	//	fwrite(&len,sizeof(len),1,fp);
	//	fwrite(cipherText,len,1,fp);	

	fprintf(fp," PASSWORD = \n%c",len);

	printf("\nGenerated Cipher \n");
	for(i=0;i<len+rem;i++){
		fprintf(fp,"%c",cipherText[i]);	
		printf("%x ",cipherText[i]);	
	}	
	printf("\n");

	char buf[1024];
	memset(buf,0,1024);
	if(len<=15){	
		sprintf(buf,"%c",'0');
		sprintf(buf+1,"%x",(char *)len);
	}
	else
		sprintf(buf,"%x",len);

	for(i=0;i<len+rem;i++){
		if(cipherText[i]<=15){
			sprintf(buf+2+i*2,"%c",'0');
			sprintf(buf+2+i*2+1,"%x",cipherText[i]);
		}
		else
			sprintf(buf+2+i*2,"%x",cipherText[i]);
		printf("%2x",cipherText[i]);
	}	

	writeXml(buf);

	fclose(fp);

	memset(cipherText,0,256);
	fp=fopen("passwd","r");	
	char temp[256],t;
	len=0;

	memset(temp,0,256);
	fscanf(fp,"%[^\n]",temp);
	fscanf(fp,"%c",&t);


	fscanf(fp,"%c",&len);	
	for(i=0;i<len+rem;i++)
		fscanf(fp,"%c",&cipherText[i]);

	printf("\nRead Cipher \n");
	for(i=0;i<len+rem;i++)
		printf("%x ",cipherText[i]);	
	printf("\n");
	
	readXml();
	nortel_decrypt(cipherText,len,decryptText);

	printf("\nDecrypted ClearText \n");
	for(i=0;i<len;i++)
		printf("%x(%c) ",decryptText[i],decryptText[i]);	
	printf("\n");
	fclose(fp);

	return 0;
}

#include <libxml/xmlmemory.h>
#include <libxml/parser.h>
#include <libxml/tree.h>

int writeXml(char *data){

	xmlNodePtr childptr;
	xmlNodePtr root_node = NULL;
	xmlDocPtr doc;
	
	doc = xmlNewDoc(BAD_CAST "1.0");
	root_node = xmlNewNode(NULL, BAD_CAST "client_profiles");
	xmlDocSetRootElement(doc, root_node);

	/*Get the root element node */
	xmlNode *root = NULL;
	root = xmlDocGetRootElement(doc);

	childptr=xmlNewTextChild(root,NULL,"profile",NULL);

	xmlNewProp(childptr,"name", "test profile");

	xmlNewTextChild(childptr, NULL, "gateway_ip", data); 
	xmlKeepBlanksDefault(0);
	xmlSaveFormatFile("a.xml",doc,1);
	xmlFreeDoc(doc);	

}



int readXml(){

	xmlNode *cur_node, *child_node;
	xmlChar *buffer,*buffer1;
	xmlDocPtr doc;
	int status=-1;
	int i=0;
	/* parse the xml file */

	doc = xmlParseFile("a.xml");
	if (doc == NULL) 
	{
# if __DEBUG__ == 1
		printf("error: could not parse file file.xml\n");
#endif 
		return -1;
	}


	/*Get the root element node */
	xmlNode *root = NULL;
	root = xmlDocGetRootElement(doc);

	if( !root || !root->name ||xmlStrcmp(root->name,"client_profiles")) { 
		xmlFreeDoc(doc);
		return -1;
	}

	/* main loop */

	for(cur_node = root->children; cur_node != NULL; cur_node = cur_node->next) 
	{

		if ( cur_node->type == XML_ELEMENT_NODE  && !xmlStrcmp(cur_node->name, (const xmlChar *) "profile")) 
		{  
			buffer= xmlGetProp(cur_node,"name");
			if(strcmp(buffer,"test profile")==0) 
			{
# if __DEBUG__ == 1
				printf("profile found\n");
#endif
				xmlFree(buffer);

				for(child_node = cur_node->children; child_node != NULL; child_node = child_node->next) 
				{
# if __DEBUG__ == 1
					printf("in side main for\n");
#endif
					/* get gateway address */

					if ( child_node->type == XML_ELEMENT_NODE  && !xmlStrcmp(child_node->name, (const xmlChar *)"gateway_ip")) 
					{

						buffer = xmlNodeGetContent(child_node);
						if(buffer) 
						{
							printf("From XML \n");
							for(i=0;i<57*2;i++)
								printf("%x(%c) ",buffer[i],buffer[i]);
							printf("\n");
							xmlFree(buffer);
						}
					}
				} //for close 
			}// inner if close
		} //if profile close 
	} // main for close 
	xmlFreeDoc(doc);
	return 0;
}
#endif

#if 0
int main(){
	char *encode,*decode;
	char clear[]="novell"; 
	int i;
	int encodelen,decodelen;
	int clearlen=strlen(clear);
	encode=malloc(1024);
	memset(encode,0,1024);
				
	decode=malloc(1024);
	memset(decode,0,1024);				
				
	nortel_encode (clear,clearlen, encode, &encodelen,STRKEY,strlen(STRKEY));
				
	for(i=0;i<encodelen;i++){
		printf("%c ",encode[i]);	
	}	
	printf("\n");
				
	nortel_decode(encode, encodelen,decode, &decodelen,STRKEY,strlen(STRKEY));
				
	for(i=0;i<decodelen;i++){
		printf("%c ",decode[i]);	
	}	
	printf("\n");
				


}
#endif
