
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

#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/pkcs12.h>
#include <netinet/in.h>
#include <netdb.h>
#include "CommonUI.h"
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>

/* cli headers */
#include "vpncExtCert.h"
//#include "cli.h"

static FILE *fpx = NULL, *fpp =NULL, *fpc = NULL, *fpca = NULL;

static int Fclose(FILE *fp)
{
    int ret = 0;
    if(fp)
    {
        ret = fclose(fp);
        fp=NULL;
    }
    return ret;
}

static int FcloseAll()
{
    Fclose(fpx);
    Fclose(fpp);
    Fclose(fpc);
    Fclose(fpca);
    return 0;
}

static int openFilesToReadAndWrite(const char *pfxFilePath)
{

    extern Inf_t Inf;
    mode_t old_mask = umask (0177);

    if (!(fpx = fopen(pfxFilePath, "rb"))) 
    {
	umask (old_mask);
#ifdef __DEBUG__
        fprintf(stderr, "Error opening file %s\n", pfxFilePath);
#endif	
        return VPNC_ERR_DCRT_OPENPFX;
    }

    if (!(fpp = fopen(Inf.userPvtKey, "w"))) 
    {
	umask (old_mask);
#ifdef __DEBUG__
        fprintf(stderr, "Error opening file %s\n", Inf.userPvtKey);
#endif	
        return VPNC_ERR_DCRT_CRTPVTKEYFL;
    }

    if (!(fpc = fopen(Inf.userCert, "w"))) 
    {
	umask (old_mask);
#ifdef __DEBUG__
        fprintf(stderr, "Error opening file %s\n", Inf.userCert);
#endif	
        return VPNC_ERR_DCRT_CRTCERTFL;
    }	
#ifdef __WANT_CA__	
    if (!(fpca = fopen(CACERT, "w"))) 
    {
	umask (old_mask);
#ifdef __DEBUG__
        fprintf(stderr, "Error opening file %s\n", CACERT);
#endif	
        return VPNC_ERR_DCRT_CRTCACERTFL;
    }	
#endif
	umask (old_mask);
    return 0;
}

static int writeCert(X509 *cert, PKCS12_SAFEBAG *safe_bag) 
{

    char sname[MAX_PATH_LEN] = {'\0'};
    char iname[MAX_PATH_LEN] = {'\0'};
    X509_NAME *subject = NULL, *issuer = NULL;

    fprintf(fpc,"    friendlyName: %s\n", PKCS12_get_friendlyname(safe_bag));

    /* friendly name belongs to the PKCS12_SAFEBAG structure */
    subject = X509_get_subject_name(cert);
    fprintf(fpc, "subject=%s\n", X509_NAME_oneline(subject, sname,MAX_PATH_LEN));
    issuer = X509_get_issuer_name(cert);
    fprintf(fpc, "issuer=%s\n", X509_NAME_oneline(issuer, iname,MAX_PATH_LEN));
    PEM_write_X509(fpc, cert);

    Fclose(fpc);	

    return 0;
}

static int writePvtKey(EVP_PKEY *pkey, PKCS12_SAFEBAG *safe_bag) 
{	
    /* friendly name belongs to the PKCS12_SAFEBAG structure */
    fprintf(fpp,"    friendlyName: %s\n", PKCS12_get_friendlyname(safe_bag));
    PEM_write_PrivateKey(fpp, pkey, NULL, NULL, 0, NULL, NULL);
    Fclose(fpp);

    return 0;
}

#ifdef __WANT_CA__

static int writeCA(STACK_OF(X509) *ca)
{ 
    char sname[MAX_PATH_LEN] = {'\0'};
    char iname[MAX_PATH_LEN] = {'\0'};
    X509_NAME *subject = NULL, *issuer = NULL;

    /* Other Certificates-I don't write now. */
    X509 *chainelem = NULL;
    int i = 0;	


#ifdef __DEBUG__
    printf("Number of chain elements:%d\n", sk_num(ca));
#endif	
    for(i = 0; i < sk_num(ca); i++)
    {
        memset(sname, 0, MAX_PATH_LEN);
        memset(iname, 0, MAX_PATH_LEN);
        chainelem = sk_X509_value(ca, i);
        fprintf(fpca, "Bag Attributes\n");
        subject = X509_get_subject_name(chainelem);
        fprintf(fpca, "subject=%s\n", X509_NAME_oneline(subject, sname,MAX_PATH_LEN));
        issuer = X509_get_issuer_name(chainelem);
        fprintf(fpca, "issuer=%s\n", X509_NAME_oneline(issuer, iname,MAX_PATH_LEN));
        PEM_write_X509(fpca, chainelem);

#if 0
        if(strcmp(X509_NAME_oneline(subject,sname,MAX_PATH_LEN), X509_NAME_oneline(issuer, iname, MAX_PATH_LEN)) == 0)
        {	
            hash = X509_subject_name_hash(chainelem);

            sprintf(cmdstr,
                    RACOON_CERT_PATH"%.8x.0", hash);

            symlink(CACERT, cmdstr);
        }
#endif
    }
    Fclose(fpca);
    return 0;

}
#endif

/*
   function extracts the private key and X509 certificate out of a pfx file.
   pfxFilePath-full path of the pfx file
   password-password required for extraction
   */

int vpnExtCerts(const char *pfxFilePath, const char *password)
{
    EVP_PKEY *pkey = NULL;

    X509 *cert = NULL;
    //STACK_OF(X509) *ca = NULL;
    PKCS12 *p12 = NULL;

    PKCS12_SAFEBAG *safe_bag = NULL;
    STACK_OF(PKCS7) *asafes = NULL;
    STACK_OF(PKCS12_SAFEBAG) *bags = NULL;
    PKCS7 *p7 = NULL; 
    ASN1_TYPE *attrib = NULL;

    int ret = 0;
    if((ret = openFilesToReadAndWrite(pfxFilePath))!=0){
        FcloseAll();

        /* error opening files */
        return ret;
    }

    SSLeay_add_all_algorithms();

    /*  Get a p12 handle */

    p12 = d2i_PKCS12_fp(fpx, NULL);
    Fclose (fpx);

    if (!p12) 
    {
#ifdef __DEBUG__
        fprintf(stderr, "Error reading PKCS#12 file: %s\n", pfxFilePath);
        ERR_print_errors_fp(stderr);
#endif	
        EVP_PBE_cleanup();
        
        /* problem with pfxfile */
        return VPNC_ERR_DCRT_READPFX;   
    }

    /* Parse the p12  */

#ifdef __WANT_CA__	
    if (!PKCS12_parse(p12, password, &pkey, &cert, &ca)) 
#else
        if (!PKCS12_parse(p12, password, &pkey, &cert, NULL)) //ca not required 
#endif
        {
#ifdef __DEBUG__
            fprintf(stderr, "Error parsing PKCS#12 file: %s\n", pfxFilePath);
            ERR_print_errors_fp(stderr);
#endif	
            EVP_PBE_cleanup();
            return VPNC_ERR_DCRT_PARSEPFX;//problem with parsing .. password?
        }

    /* parse authsafes */

    if(!(asafes = PKCS12_unpack_authsafes(p12))){
#ifdef __DEBUG__
        fprintf(stderr, "Unpack authsafes in PKCS#12 structure failed.\n");  
#endif	
    }
    else
    {
        int asafescount = 0, bagnid = 0;
        for(asafescount=0; asafescount < sk_PKCS7_num(asafes); asafescount++)
        {
            p7 = sk_PKCS7_value(asafes, asafescount);
            bagnid = OBJ_obj2nid(p7->type);
#ifdef __DEBUG__
            fprintf(stderr, "Authsafe %d: bagnid = %d\n", asafescount, bagnid);
#endif	

            if(bagnid == NID_pkcs7_data)
                bags = PKCS12_unpack_p7data(p7);
            else 
                continue;

            if(!bags)
                sk_PKCS7_pop_free(asafes, PKCS7_free);

#ifdef __DEBUG__
            fprintf(stderr, "Num of safebags = %d\n", sk_PKCS12_SAFEBAG_num(bags));
#endif	

            /* taking only the first bag for now */
            safe_bag=sk_PKCS12_SAFEBAG_value(bags, 0);
#ifdef __DEBUG__
            printf("bag type=%d\n",M_PKCS12_bag_type(safe_bag));
#endif	

            if(safe_bag)
            {
                fprintf(fpp, "Bag Attributes\n");
                fprintf(fpc, "Bag Attributes\n");
                /* get localkeyid */	
                attrib=PKCS12_get_attr(safe_bag, 157);
                if(attrib )
                {
                    int charcnt=0;
                    fprintf(fpp,"    localKeyID: ");
                    fprintf(fpc,"    localKeyID: ");
                    while(charcnt < attrib->value.octet_string->length)
                    {
                        fprintf(fpp,"%02X ", (unsigned char)attrib->value.octet_string->data[charcnt]);
                        fprintf(fpc,"%02X ", (unsigned char)attrib->value.octet_string->data[charcnt]);
                        ++charcnt;
                    }
                    fprintf(fpp,"\n");
                    fprintf(fpc,"\n");
                }	
                else{
#ifdef __DEBUG__
                    fprintf(stderr,"Localkey id is null\n");
#endif	

                }
            }	

        }
    }

    if (pkey && cert ) 
    {
        writePvtKey(pkey,safe_bag); //error check??
        writeCert(cert,safe_bag); //error check ??
    }
    else
    {
#ifdef __DEBUG__
        fprintf(stderr, "Error retrieving X509 certificate\n");
#endif	
        FcloseAll();
        EVP_PBE_cleanup();		
        return VPNC_ERR_DCRT_RTRCERT;
    }

#ifdef __WANT_CA__

    if (ca && sk_num(ca)) 
    {
        writeCA(ca);
    }
#endif

    PKCS12_free(p12);
    EVP_PBE_cleanup();
    return 0;	
}

/*
   int main(){
   if(vpnExtCerts("test_remote_key.p12","novell")<0){
   printf("Error\n");
   return -1;
   }
   return 0;
   }
*/
