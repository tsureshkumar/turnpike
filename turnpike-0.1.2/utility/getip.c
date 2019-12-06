
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

#include <asm/types.h>
#include <stdio.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <sys/types.h>
#include <errno.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#include "getip.h"

#define MAX_BUF_SIZE 1024
#define MAX_RECV_BUF_SIZE 16384

#if 0
Structure defs from netlink.h 
struct nlmsghdr
{
	__u32		nlmsg_len;	/* Length of message including header */
	__u16		nlmsg_type;	/* Message content */
	__u16		nlmsg_flags;	/* Additional flags */
	__u32		nlmsg_seq;	/* Sequence number */
	__u32		nlmsg_pid;	/* Sending process PID */
};

Structure defs from rtnetlink.h 

struct rtmsg
{
	unsigned char		rtm_family;
	unsigned char		rtm_dst_len;
	unsigned char		rtm_src_len;
	unsigned char		rtm_tos;

	unsigned char		rtm_table;	/* Routing table id */
	unsigned char		rtm_protocol;	/* Routing protocol; see below	*/
	unsigned char		rtm_scope;	/* See below */	
	unsigned char		rtm_type;	/* See below	*/

	unsigned		rtm_flags;
};


Structure from socket.h

struct msghdr {
	void	*	msg_name;	/* Socket name			*/
	int		msg_namelen;	/* Length of name		*/
	struct iovec *	msg_iov;	/* Data blocks			*/
	__kernel_size_t	msg_iovlen;	/* Number of blocks		*/
	void 	*	msg_control;	/* Per protocol magic (eg BSD file descriptor passing) */
	__kernel_size_t	msg_controllen;	/* Length of cmsg list */
	unsigned	msg_flags;
};


#endif

typedef struct rtnetlink_command {
    
    struct nlmsghdr n;
    struct rtmsg r;
    char  buf[MAX_BUF_SIZE];
    
} rtnetlink_command_t;


static int pack_into_msg_struct(struct sockaddr_nl *nladdr, struct iovec *iov, struct msghdr *msg)
{
    nladdr->nl_family = AF_NETLINK;
    nladdr->nl_pid = 0;
    nladdr->nl_groups = 0;
    
    /* Prepare the message */
    /* TODO: Can be done during declaration itself. Put it separately here for readability */
    msg->msg_name = (void *)nladdr;
    msg->msg_namelen = sizeof(*nladdr);
    msg->msg_iov = iov; /* base and len */
    msg->msg_iovlen = 1; /* only one iov message */
    msg->msg_control = NULL; 
    msg->msg_controllen = 0;
    msg->msg_flags = 0;
    
    return 0; 
}

static int send_to_netlink(int fd, struct nlmsghdr *n)
{

    int rc = 0;
    struct iovec iov = { 0 };
    struct msghdr msg = { 0 };
    struct sockaddr_nl nladdr= { 0 };

    /* Prepare iov */
    /* TODO: Can be done during declaration itself. Put it separately here for readability */
    iov.iov_base = (void *)n;
    iov.iov_len = n->nlmsg_len;

    if(pack_into_msg_struct(&nladdr, &iov, &msg)<0){
        /*printf("Error packing into msg struct \n");*/
        return -1;
    }
    
    if ((rc = sendmsg(fd, &msg, 0)) < 0) {

/*        printf("Cannot send to rtnetlink\n"); */
        return -1;
    }
    return 0;
}

static int recv_from_netlink(int fd, struct nlmsghdr *reply)
{
    char buf[MAX_RECV_BUF_SIZE] = {0}; // For recv buffer.
    struct iovec iov = { 0 };
    int rem = 0;
    struct msghdr msg = { 0 };
    struct sockaddr_nl nladdr= { 0 };
    struct nlmsghdr *h = NULL;
    
    memset(buf,0,sizeof(buf));
    iov.iov_base = buf;
    iov.iov_len = sizeof(buf);
    
    if(pack_into_msg_struct(&nladdr, &iov, &msg)<0){
        /* printf("Error packing into msg struct \n"); */
        return -1;
    }

    while (1) {
        rem = recvmsg(fd, &msg, 0);

        if (rem < 0) {
            continue;
        }
        if (rem == 0) {
            /* printf("EOF \n"); */
            return -1;
        }
        if (msg.msg_namelen != sizeof(nladdr)) {
            return -1;
        }
        for (h = (struct nlmsghdr*)buf; rem >= sizeof(*h); ) {
            int len = h->nlmsg_len;
            int l = len - sizeof(*h);

            if (l<0 || len>rem) {
                if (msg.msg_flags & MSG_TRUNC) {
                    /* printf("Truncated message\n"); */
                    return -1;
                }
/*                printf("!!!malformed message: len=%d\n", len); */
                return -1;
            }


            if (h->nlmsg_type == NLMSG_ERROR) {
                return -1;
            }
            if (reply) {
                memcpy(reply, h, h->nlmsg_len);
                return 0;
            }

         /*   printf("Something is wrong!!!\n"); */

            rem -= NLMSG_ALIGN(len);
            h = (struct nlmsghdr*)((char*)h + NLMSG_ALIGN(len));
        }
        if (msg.msg_flags & MSG_TRUNC) {
         /*   printf("Message truncated\n"); */
            continue;
        }
        if (rem) {
/*            printf("More than expected length %d\n", rem); */
            return -1;
        }
    }
    return -1;
}


static int fill_req_header_and_rtm_command(rtnetlink_command_t *req, const char *ip)
{
 
    struct rtattr *rta = NULL;
    int len = 4; /* IPV4 Address - len is 4 bytes */
    struct in_addr in = { 0 };
    
    memset(req, 0, sizeof(*req));
    
    /* Fill n */
    req->n.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));
    req->n.nlmsg_flags = NLM_F_REQUEST;
    req->n.nlmsg_type = RTM_GETROUTE;
    req->n.nlmsg_seq = 1;
    
    /* Fill r */
    req->r.rtm_family = AF_INET;
    req->r.rtm_table = 0;
    req->r.rtm_protocol = 0;
    req->r.rtm_scope = 0;
    req->r.rtm_type = 0;
    req->r.rtm_src_len = 0;
    req->r.rtm_dst_len = 0;
    req->r.rtm_tos = 0;
   
    /*rta will point into the buffer*/
    
    rta = (struct rtattr *) (((void *) (&req->n)) + NLMSG_ALIGN(req->n.nlmsg_len));

    rta->rta_type = RTA_DST;
    rta->rta_len = RTA_LENGTH(len);

   /* Address in host order is the RTA data */ 
    if(inet_aton(ip, &in) <0 ){
/*        printf("Conversion error \n"); */
        return -1;
    }

    memcpy(RTA_DATA(rta), &in.s_addr, len);
    req->n.nlmsg_len = NLMSG_ALIGN(req->n.nlmsg_len) + RTA_ALIGN(RTA_LENGTH(len));

    req->r.rtm_dst_len = len * 8; //in bits
    return 0;
    
}


static int parse_response(struct nlmsghdr *n, int len, char *source, char *oif)
{
    struct rtmsg *r = NULL;
    struct rtattr *rta = NULL;
    int match = 0;
    unsigned char src[4] ={'\0'};
    
    r = NLMSG_DATA(n);

    rta = RTM_RTA(r);
    while (RTA_OK(rta, len)) {
        switch(rta->rta_type){
            case RTA_PREFSRC:
                memcpy(src, RTA_DATA(rta), 4 );
                sprintf(source,"%d.%d.%d.%d",src[0], src[1],src[2],src[3]);
                match++;
                break;
            case RTA_OIF:
               /*TODO: get this if index to if name. looks like a dump of all interfaces is req to get the index to name mapping. */
                sprintf(oif,"if%d",*(int *)RTA_DATA(rta));
                match++;
                break;
            default:           
                break;
        }
        rta = RTA_NEXT(rta,len);         
    }
    if(match == 2)
        return 0;
    else
        return -1;

}
int getip(const char *ip, char *source, char *oif)
{
    rtnetlink_command_t req, reply;
    int sock = 0;
    
    /* Create Socket */
    if((sock = socket(PF_NETLINK, SOCK_RAW, NETLINK_ROUTE)) < 0){
/*        printf("Socket Creation error \n"); */
          return -1;

    }
    
    if(fill_req_header_and_rtm_command(&req, ip)<0){
        /*     printf("Error filling req data struct \n"); */
        close(sock);
        return -1;
    }
    
    if(send_to_netlink (sock, &req.n )<0){ 
/*        printf("Send error \n"); */
        close(sock);
        return -1;
    }

    if(recv_from_netlink (sock, &reply.n )<0){ 
/*        printf("Reply error \n"); */
        close(sock);
        return -1;
    }
    
    close(sock);
   
    /* Parse the reply */ 
    if(parse_response(&reply.n, req.n.nlmsg_len, source, oif) < 0){
/*        printf("Response parse error \n"); */
        return -1;
    }
    
    return 0;
}

#if 0
int main(int argc, char **argv)
{
    unsigned  char *source = NULL, *oif = NULL;

    if(argc <2){
        printf("Usage: %s <ip address>\n", argv[0]);
        return -1;
    }
    source = (unsigned char *)malloc(16 * sizeof(unsigned char));
    memset (source , 0 , 16);
    oif = (unsigned char *)malloc(16 * sizeof(unsigned char));
    memset (oif , 0 , 16);
    
    if(getip(argv[1], source, oif)<0){
        printf("getip returned error \n");
        return -1;
    }
    printf("source = %s, srcif = %s\n",source,oif);

    free(source);
    free(oif);
    return 0; 
}
# endif
