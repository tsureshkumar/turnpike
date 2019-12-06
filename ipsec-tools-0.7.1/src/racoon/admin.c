/*	$NetBSD: admin.c,v 1.17.6.2 2008/06/18 07:30:19 mgrooms Exp $	*/

/* Id: admin.c,v 1.25 2006/04/06 14:31:04 manubsd Exp */

/*
 * Copyright (C) 1995, 1996, 1997, and 1998 WIDE Project.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the project nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE PROJECT AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE PROJECT OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include "config.h"

#include <sys/types.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/signal.h>
#include <sys/stat.h>
#include <sys/un.h>

#include <arpa/inet.h>
#include <net/pfkeyv2.h>

#include <netinet/in.h>
#include PATH_IPSEC_H


#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <netdb.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#ifdef ENABLE_HYBRID
#include <resolv.h>
#endif

#include "var.h"
#include "misc.h"
#include "vmbuf.h"
#include "plog.h"
#include "sockmisc.h"
#include "debug.h"

#include "schedule.h"
#include "localconf.h"
#include "remoteconf.h"
#include "grabmyaddr.h"
#include "isakmp_var.h"
#include "isakmp.h"
#include "oakley.h"
#include "handler.h"
#include "evt.h"
#include "pfkey.h"
#include "ipsec_doi.h"
#include "admin.h"
#include "admin_var.h"
#include "isakmp_inf.h"
#ifdef ENABLE_HYBRID
#include "isakmp_cfg.h"
#endif
#include "session.h"
#include "gcmalloc.h"

#include "algorithm.h"
#include "sainfo.h"

#ifdef PLUGINS_SUPPORT
#include "plugin_frame/common.h"
#endif

#include "cfparse_proto.h"

#ifdef ENABLE_ADMINPORT
char *adminsock_path = ADMINSOCK_PATH;
uid_t adminsock_owner = 0;
gid_t adminsock_group = 0;
mode_t adminsock_mode = 0600;

static const char *protocol[] = {
	"esp", "ah", "ipcomp"
};

static const char *mode[] = {
	"tunnel", "transport"
};

static struct sockaddr_un sunaddr;
static int admin_process __P((int, char *));
static int admin_reply __P((int, struct admin_com *, vchar_t *));

static void isakmp_flush_sa __P((struct ph1handle *, char *, char *));
int add_policy_to_SPD __P((struct sockaddr_storage *,
			struct sockaddr_storage *, struct admin_com_ph2policy *));

int
admin_handler()
{
	int so2;
	struct sockaddr_storage from;
	socklen_t fromlen = sizeof(from);
	struct admin_com com;
	char *combuf = NULL;
	int len, error = -1;

	so2 = accept(lcconf->sock_admin, (struct sockaddr *)&from, &fromlen);
	if (so2 < 0) {
		plog(LLV_ERROR, LOCATION, NULL,
			"failed to accept admin command: %s\n",
			strerror(errno));
		return -1;
	}

	/* get buffer length */
	while ((len = recv(so2, (char *)&com, sizeof(com), MSG_PEEK)) < 0) {
		if (errno == EINTR)
			continue;
		plog(LLV_ERROR, LOCATION, NULL,
			"failed to recv admin command: %s\n",
			strerror(errno));
		goto end;
	}

	/* sanity check */
	if (len < sizeof(com)) {
		plog(LLV_ERROR, LOCATION, NULL,
			"invalid header length of admin command\n");
		goto end;
	}

	/* get buffer to receive */
	if ((combuf = racoon_malloc(com.ac_len)) == 0) {
		plog(LLV_ERROR, LOCATION, NULL,
			"failed to alloc buffer for admin command\n");
		goto end;
	}

	/* get real data */
	while ((len = recv(so2, combuf, com.ac_len, 0)) < 0) {
		if (errno == EINTR)
			continue;
		plog(LLV_ERROR, LOCATION, NULL,
			"failed to recv admin command: %s\n",
			strerror(errno));
		goto end;
	}

	if (com.ac_cmd == ADMIN_RELOAD_CONF) {
		/* reload does not work at all! */
		signal_handler(SIGHUP);
		goto end;
	}

	error = admin_process(so2, combuf);

    end:
	(void)close(so2);
	if (combuf)
		racoon_free(combuf);

	return error;
}

/*
 * main child's process.
 */
int
admin_process(so2, combuf)
	int so2;
	char *combuf;
{
	struct admin_com *com = (struct admin_com *)combuf;
	vchar_t *buf = NULL;
	vchar_t *id = NULL;
	vchar_t *key = NULL;
	int idtype = 0;
	int error = -1;
	int i = 0;

	com->ac_errno = 0;

	switch (com->ac_cmd) {
	case ADMIN_RELOAD_CONF:
		/* don't entered because of proccessing it in other place. */
		plog(LLV_ERROR, LOCATION, NULL, "should never reach here\n");
		goto out;

	case ADMIN_SHOW_SCHED:
	{
		caddr_t p = NULL;
		int len;

		com->ac_errno = -1;

		if (sched_dump(&p, &len) == -1)
			goto out2;

		if ((buf = vmalloc(len)) == NULL)
			goto out2;

		memcpy(buf->v, p, len);

		com->ac_errno = 0;
out2:
		racoon_free(p);
		break;
	}

	case ADMIN_SHOW_EVT:
		/* It's not really an error, don't force racoonctl to quit */
		if ((buf = evt_dump()) == NULL)
			com->ac_errno = 0;
		break;

	case ADMIN_SHOW_SA:
	case ADMIN_FLUSH_SA:
	    {
		switch (com->ac_proto) {
		case ADMIN_PROTO_ISAKMP:
			switch (com->ac_cmd) {
			case ADMIN_SHOW_SA:
				buf = dumpph1();
				if (buf == NULL)
					com->ac_errno = -1;
				break;
			case ADMIN_FLUSH_SA:
				flushph1();
				break;
			}
			break;
		case ADMIN_PROTO_IPSEC:
		case ADMIN_PROTO_AH:
		case ADMIN_PROTO_ESP:
			switch (com->ac_cmd) {
			case ADMIN_SHOW_SA:
			    {
				u_int p;
				p = admin2pfkey_proto(com->ac_proto);
				if (p == -1)
					goto out;
				buf = pfkey_dump_sadb(p);
				if (buf == NULL)
					com->ac_errno = -1;
			    }
				break;
			case ADMIN_FLUSH_SA:
				pfkey_flush_sadb(com->ac_proto);
				break;
			}
			break;

		case ADMIN_PROTO_INTERNAL:
			switch (com->ac_cmd) {
			case ADMIN_SHOW_SA:
				buf = NULL; /*XXX dumpph2(&error);*/
				if (buf == NULL)
					com->ac_errno = error;
				break;
			case ADMIN_FLUSH_SA:
				/*XXX flushph2();*/
				com->ac_errno = 0;
				break;
			}
			break;

		default:
			/* ignore */
			com->ac_errno = -1;
		}
	    }
		break;

	case ADMIN_DELETE_SA: {
		struct ph1handle *iph1;
		struct sockaddr *dst;
		struct sockaddr *src;
		char *loc, *rem;

		src = (struct sockaddr *)
			&((struct admin_com_indexes *)
			    ((caddr_t)com + sizeof(*com)))->src;
		dst = (struct sockaddr *)
			&((struct admin_com_indexes *)
			    ((caddr_t)com + sizeof(*com)))->dst;

		loc = racoon_strdup(saddrwop2str(src));
		rem = racoon_strdup(saddrwop2str(dst));
		STRDUP_FATAL(loc);
		STRDUP_FATAL(rem);

		if ((iph1 = getph1byaddrwop(src, dst)) == NULL) {
			plog(LLV_ERROR, LOCATION, NULL,
			    "phase 1 for %s -> %s not found\n", loc, rem);
		} else {
			if (iph1->status == PHASE1ST_ESTABLISHED)
				isakmp_info_send_d1(iph1);
			purge_remote(iph1);
		}

		racoon_free(loc);
		racoon_free(rem);

		break;
	}

#ifdef ENABLE_HYBRID
	case ADMIN_LOGOUT_USER: {
		struct ph1handle *iph1;
		char *user;
		int found = 0;

		if (com->ac_len > sizeof(com) + LOGINLEN + 1) {
			plog(LLV_ERROR, LOCATION, NULL,
			    "malformed message (login too long)\n");
			break;
		}

		user = (char *)(com + 1);
		found = purgeph1bylogin(user);
		plog(LLV_INFO, LOCATION, NULL,
		    "deleted %d SA for user \"%s\"\n", found, user);

		break;
	}
#endif

	case ADMIN_DELETE_ALL_SA_DST: {
		struct ph1handle *iph1;
		struct sockaddr *dst;
		char *loc, *rem;

		dst = (struct sockaddr *)
			&((struct admin_com_indexes *)
			    ((caddr_t)com + sizeof(*com)))->dst;

		rem = racoon_strdup(saddrwop2str(dst));
		STRDUP_FATAL(rem);

		plog(LLV_INFO, LOCATION, NULL,
		    "Flushing all SAs for peer %s\n", rem);

		while ((iph1 = getph1bydstaddrwop(dst)) != NULL) {
			loc = racoon_strdup(saddrwop2str(iph1->local));
			STRDUP_FATAL(loc);

			if (iph1->status == PHASE1ST_ESTABLISHED)
				isakmp_info_send_d1(iph1);
			purge_remote(iph1);

			racoon_free(loc);
		}
		
		racoon_free(rem);

		break;
	}

	case ADMIN_ESTABLISH_SA_PSK: {
		struct admin_com_psk *acp;
		char *data;

		com->ac_cmd = ADMIN_ESTABLISH_SA;

		acp = (struct admin_com_psk *)
		    ((char *)com + sizeof(*com) +
		    sizeof(struct admin_com_indexes));

		idtype = acp->id_type;

		if ((id = vmalloc(acp->id_len)) == NULL) {
			plog(LLV_ERROR, LOCATION, NULL,
			    "cannot allocate memory: %s\n",
			    strerror(errno));
			break;
		}
		data = (char *)(acp + 1);
		memcpy(id->v, data, id->l);

		if ((key = vmalloc(acp->key_len)) == NULL) {
			plog(LLV_ERROR, LOCATION, NULL,
			    "cannot allocate memory: %s\n",
			    strerror(errno));
			vfree(id);
			id = NULL;
			break;
		}
		data = (char *)(data + acp->id_len);
		memcpy(key->v, data, key->l);
	}
	/* FALLTHROUGH */
	case ADMIN_ESTABLISH_SA:
	    {
		struct sockaddr *dst;
		struct sockaddr *src;
		src = (struct sockaddr *)
			&((struct admin_com_indexes *)
			    ((caddr_t)com + sizeof(*com)))->src;
		dst = (struct sockaddr *)
			&((struct admin_com_indexes *)
			    ((caddr_t)com + sizeof(*com)))->dst;

		switch (com->ac_proto) {
		case ADMIN_PROTO_ISAKMP: {
			struct remoteconf *rmconf;
			struct sockaddr *remote = NULL;
			struct sockaddr *local = NULL;
			u_int16_t port;

			com->ac_errno = -1;

			/* search appropreate configuration */
			rmconf = getrmconf(dst);
			if (rmconf == NULL) {
				plog(LLV_ERROR, LOCATION, NULL,
					"no configuration found "
					"for %s\n", saddrwop2str(dst));
				goto out1;
			}

			/* get remote IP address and port number. */
			if ((remote = dupsaddr(dst)) == NULL)
				goto out1;

			port = extract_port(rmconf->remote);
			if (set_port(remote, port) == NULL)
				goto out1;

			/* get local address */
			if ((local = dupsaddr(src)) == NULL)
				goto out1;

			port = getmyaddrsport(local);
			if (set_port(local, port) == NULL)
				goto out1;

#ifdef ENABLE_HYBRID
			/* Set the id and key */
			if (id && key) {
				if (xauth_rmconf_used(&rmconf->xauth) == -1)
					goto out1;

				if (rmconf->xauth->login != NULL) {
					vfree(rmconf->xauth->login);
					rmconf->xauth->login = NULL;
				}
				if (rmconf->xauth->pass != NULL) {
					vfree(rmconf->xauth->pass);
					rmconf->xauth->pass = NULL;
				}

				rmconf->xauth->login = id;
				rmconf->xauth->pass = key;
			}
#endif

			plog(LLV_INFO, LOCATION, NULL,
				"accept a request to establish IKE-SA: "
				"%s\n", saddrwop2str(remote));

			/* begin ident mode */
			if (isakmp_ph1begin_i(rmconf, remote, local) < 0)
				goto out1;

			com->ac_errno = 0;
out1:
			if (local != NULL)
				racoon_free(local);
			if (remote != NULL)
				racoon_free(remote);
			break;
		}
		case ADMIN_PROTO_AH:
		case ADMIN_PROTO_ESP:
			break;
		default:
			/* ignore */
			com->ac_errno = -1;
		}
	    }
		break;
#ifdef ENABLE_AP_CLIENTMODE
	case ADMIN_PUSH_PHASE1CONFIG:
		{
			struct sockaddr *dst = NULL;
			struct remoteconf *remoteconf = NULL, *new_rmconf = NULL;
			struct admin_com_ph1config *ph1ptr = NULL;
			struct idspec  *id = NULL;
			vchar_t *my_id = NULL;
			vchar_t *peer_id_val = NULL;

#if 0
			cfreparse();
#endif

			ph1ptr = (struct admin_com_ph1config *)
				((caddr_t)com + sizeof(*com));

			dst = (struct sockaddr *)&ph1ptr->dst;

			remoteconf = getrmconf(dst);

			if(!remoteconf || remoteconf->remote->sa_family == AF_UNSPEC){
				/* we've hit the anonymous remote configuration */
				remoteconf = new_rmconf = newrmconf();
				if(remoteconf == NULL){
					plog(LLV_ERROR, LOCATION, NULL,
							"Failed to get new remoteconf\n");
					goto out;
				}
				remoteconf->remote = (struct sockaddr *)
					racoon_calloc(1,sizeof(struct sockaddr));
				if(remoteconf->remote == NULL){
					plog(LLV_ERROR, LOCATION, NULL,
							"Failed to allocate for remote IPAddr\n");
					delrmconf(remoteconf);
					goto out;
				}
				memcpy(remoteconf->remote, dst, sizeof(struct sockaddr));
			}

			if(remoteconf->etypes == NULL){
				remoteconf->etypes = (struct etypes *)racoon_calloc
					(1,sizeof(struct etypes));
				if(remoteconf->etypes == NULL){
					plog(LLV_ERROR, LOCATION, NULL,
							"Failed to allocate for exchange type list\n");
					delrmconf(remoteconf);
					goto out;
				}
			}

			remoteconf->etypes->type = ph1ptr->mode;
			remoteconf->proposal = NULL;
			remoteconf->verify_cert = ph1ptr->verify_cert;
#if 0
			//changes to be made - begin
			remoteconf->certtype = ISAKMP_CERT_X509SIGN;
			remoteconf->mycertfile = strdup("usercert.pem");
			remoteconf->myprivfile = strdup("userkeyunenc.pem");
			//changes to be made - end


			remoteconf->certtype = ph1ptr->certtype;
			strcpy(remoteconf->mycertfile, ph1ptr->mycertfile);
			strcpy(remoteconf->myprivfile,ph1ptr->myprivfile);
			strcpy(remoteconf->peerscertfile,ph1ptr->peerscertfile);
#endif
			/* my Identifier */
			remoteconf->idvtype = ph1ptr->my_identifier_type;
			if(ph1ptr->my_identifier_len > 0){
				/* populate my_identifier's value */
				if ((my_id = vmalloc(ph1ptr->my_identifier_len))
						== NULL) {
					plog(LLV_ERROR, LOCATION, NULL,
							"cannot allocate memory: %s\n",
							strerror(errno));
					delrmconf(remoteconf);
					goto out;
				}
				memcpy(my_id->v, ph1ptr->id, my_id->l);

				if(set_identifier(&remoteconf->idv,
							remoteconf->idvtype, my_id) != 0){
					plog(LLV_ERROR, LOCATION, NULL,
							"Failed to set my identifier\n");

					vfree(my_id);
					delrmconf(remoteconf);
					goto out;
				}
			}

			/* peer Identifiers */
			remoteconf->verify_identifier = ph1ptr->verify_identifier;

			if(remoteconf->verify_identifier == TRUE){
				int i = 0, peer_id_hdrlen = 0;
				struct peer_identifier *peer_id =
					(struct peer_identifier *)
					(ph1ptr->id+ph1ptr->my_identifier_len);

				peer_id_hdrlen = sizeof(struct peer_identifier);

				for( ; i < ph1ptr->num_peer_identifier ;
						i++, peer_id += peer_id_hdrlen + peer_id->id_len - 1){
					id = newidspec();
					if (id == NULL) {
						plog(LLV_ERROR, LOCATION, NULL,
								"failed to allocate idspec\n");
						delrmconf(remoteconf);
						vfree(my_id);
						racoon_free(id);
						goto out;
					}

					/* populate peer_identifier's value */
					if ((peer_id_val = vmalloc(peer_id->id_len)) == NULL) {
						plog(LLV_ERROR, LOCATION, NULL,
								"cannot allocate memory: %s\n",
								strerror(errno));
						racoon_free(id);
						vfree(my_id);
						delrmconf(remoteconf);
						goto out;
					}
					memcpy(peer_id_val->v, peer_id->idv, peer_id_val->l);

					if (set_identifier
							(&id->id, peer_id->id_type, peer_id_val) != 0){
						plog(LLV_ERROR, LOCATION, NULL,
								"failed to set identifer\n");
						vfree(peer_id_val);
						racoon_free(id);
						vfree(my_id);
						delrmconf(remoteconf);
						goto out;
					}
					id->idtype = peer_id->id_type;
					genlist_append (remoteconf->idvl_p, id);
				}
			}
			if (new_rmconf)
				insrmconf(remoteconf);
		}
		break;
	case ADMIN_PUSH_PHASE1PROPOSAL:
		{
			struct admin_com_ph1proposal_list *ph1_proposal_list = NULL;
			struct admin_com_ph1proposal *ph1_proposal = NULL;
			struct sockaddr *dst = NULL;
			struct remoteconf *remoteconf = NULL;
			struct proposalspec *prspec = NULL;
			struct isakmpsa *new_proposal = NULL;
			int i = 0;

			ph1_proposal_list =
				(struct admin_com_ph1proposal_list *)
				((caddr_t)com + sizeof(*com));

			ph1_proposal = ph1_proposal_list->ph1proposal;
			dst = (struct sockaddr *)&ph1_proposal_list->dst;

			remoteconf = getrmconf_strict(dst,0);
			if(!remoteconf || remoteconf->remote->sa_family == AF_UNSPEC){
				/* we've hit the anonymous remote configuration */
				plog(LLV_ERROR, LOCATION, NULL,
						"Failed to get remoteconf for %s\n",
						saddr2str(dst));
				goto out;
			}

			/*  Got the corresponding remoteconf. Add the policies */
			for (i = 0;i<ph1_proposal_list->num_proposal;
					i++, ph1_proposal++){
				new_proposal = newisakmpsa();
				if (new_proposal == NULL){
					plog(LLV_ERROR, LOCATION, NULL,
							"Failed to allocate new isakmpsa\n");
					goto out;
				}
				new_proposal->lifetime = oakley_get_defaultlifetime();
				new_proposal->enctype = ph1_proposal->encryption_algo;
				new_proposal->authmethod = ph1_proposal->auth_method;
				new_proposal->hashtype = ph1_proposal->hash_algo;
				new_proposal->dh_group = ph1_proposal->dh_group;

				insisakmpsa(new_proposal, remoteconf);
			}

			/* DH group settting if aggressive mode is there. */
			if (check_etypeok(remoteconf, ISAKMP_ETYPE_AGG) != NULL) {
				struct isakmpsa *p;
				int b = 0;

				/* DH group */
				for (p = remoteconf->proposal; p; p = p->next) {
					if (b == 0 || (b && b == p->dh_group)) {
						b = p->dh_group;
						continue;
					}
					plog(LLV_ERROR, LOCATION, NULL,
							"DH group must be equal "
							"in all proposals "
							"when aggressive mode is "
							"used\n");
					goto out;
				}
				remoteconf->dh_group = b;

				if (remoteconf->dh_group == 0) {
					plog(LLV_ERROR, LOCATION, NULL,
							"DH group must be set in the proposal\n");
					goto out;
				}

				/* DH group settting if PFS is required. */
				if (oakley_setdhgroup(remoteconf->dh_group,
							&remoteconf->dhgrp) < 0) {
					plog(LLV_ERROR, LOCATION, NULL,
							"failed to set DH value.\n");
					goto out;
				}
			}
		}
		break;
	case ADMIN_PUSH_PHASE2CONFIG:
		{
			struct admin_com_ph2config *ph2ptr = NULL;
			struct admin_com_ph2policy *ph2policy = NULL;
			struct admin_com_ph2_ikeattrib *ph2ikeattrib = NULL;
			struct sainfo   *new_sainfo = NULL,
							*check = NULL,
							*old_sainfo = NULL;
			struct sockaddr_storage *src_end_point = NULL,
									*dst_end_point = NULL;
			struct sainfoalg *alg = NULL;
			struct sockaddr *dst_addr = NULL;
			vchar_t *s_id = NULL, *d_id = NULL;
			short   num_ph2_policies = 0;
			int i = 0, sa_count = 0;
			int encalgtype = 0, hmacalgtype = 0;


			ph2ptr = (struct admin_com_ph2config *)
				((caddr_t)com + sizeof(*com));
			ph2policy = (struct admin_com_ph2policy *)(ph2ptr->policy);

			for(; i < ph2ptr->num_ph2_policies; i++, ph2policy++){
				/* push policy to SPD */
				if (add_policy_to_SPD
						(&ph2ptr->src_end_point, &ph2ptr->dst_end_point,
						 ph2policy) == -1)
					continue;
			}

		}
		break;
	case ADMIN_DISCONNECT_DST:
		{
			struct ph1handle *iph1;
			struct sockaddr *dst;
			char *loc, *rem;
			int pfkey_proto, pfkey_so;;

			dst = (struct sockaddr *)
				&((struct admin_com_indexes *)
						((caddr_t)com + sizeof(*com)))->dst;

			if ((rem = strdup(saddrwop2str(dst))) == NULL) {
				plog(LLV_ERROR, LOCATION, NULL,
						"failed to allocate memory\n");
				break;
			}

			plog(LLV_INFO, LOCATION, NULL,
					"Flushing all SA for peer %s\n", rem);

			while ((iph1 = getph1bydstaddrwop(dst)) != NULL) {
				if ((loc = strdup(saddrwop2str(iph1->local))) == NULL){
					plog(LLV_ERROR, LOCATION, NULL,
							"failed to allocate memory\n");
					break;
				}

				/* flush all SAs associated with this connection */
				if((pfkey_so = pfkey_open()) < 0){
					plog(LLV_ERROR, LOCATION, NULL,
							"pfkey_open failed\n");
				}
				else {
					//pfkey_proto = admin2pfkey_proto(com->ac_proto);
					//struct sockaddr_in sa_dst, sa_src;
					if(pfkey_send_spdflush(pfkey_so) == -1){
						plog(LLV_ERROR, LOCATION, NULL,
								"pfkey_send_spdflush failed\n");
					}
					if(pfkey_send_flush(
								pfkey_so, SADB_SATYPE_UNSPEC) == -1){
						plog(LLV_ERROR, LOCATION, NULL,
								"pfkey_send_sadflush failed\n");
					}
					/*      sa_dst.sin_family = AF_INET;
							sa_dst.sin_addr.s_addr = ((struct sockaddr_in *)(iph1->remote))->sin_addr.s_addr;
							sa_dst.sin_port = 0;

							sa_src.sin_family = AF_INET;
							sa_src.sin_addr.s_addr = ((struct sockaddr_in *)(iph1->local))->sin_addr.s_addr;
							sa_src.sin_port = 0;

							if (pfkey_send_delete_all(pfkey_so,
							pfkey_proto, IPSEC_MODE_TUNNEL,
							(struct sockaddr *)&sa_src, (struct sockaddr *)&sa_dst) == -1) {
							plog(LLV_ERROR, LOCATION, NULL,
							"delete_all %s -> %s failed \n",
							rem, loc
							);
							}
							*/
					pfkey_close(pfkey_so);
				}
				isakmp_flush_sa(iph1, loc, rem);

				racoon_free(loc);
			}
			racoon_free(rem);
#ifdef PLUGINS_SUPPORT
			tpike_deregister_plugin_all();
#endif
		}
		break;
	case ADMIN_REPARSE_RACOON_CONF:
		{
			int file_name_len;
			char conf_file_name[512];
			struct stat finfo;
			caddr_t recvd_data = NULL;

			/* Get the params */
			recvd_data = (caddr_t)com + sizeof(*com);
			file_name_len = *((int *)(recvd_data));
			recvd_data += sizeof(int);

			if (file_name_len >= sizeof(conf_file_name))
				goto out;

			memcpy(conf_file_name,
					(char *)(recvd_data), file_name_len);

			conf_file_name[file_name_len] = '\0';

			/* Check for File security */
			if (stat(conf_file_name, &finfo) != 0){
				plog(LLV_ERROR, LOCATION, NULL,
						"stat failed for file %s : %s\n",
						conf_file_name, strerror(errno));
				goto out;
			}
			/* Checking to see if the file has the same owner or group
			 * as adminsock
			 */
			if ((finfo.st_uid != adminsock_owner) &&
					(finfo.st_gid != adminsock_group)) {
				plog(LLV_ERROR, LOCATION, NULL,
						"Group for the conf file %s does not match"
						"with the group of admin port(%d:%d)\n",
						conf_file_name, finfo.st_gid, adminsock_group);
				goto out;
			}


			/* Verify that the file does not give more
			 * permissions than what is allowed for adminsock
			 */
			mode_t curr_mode = finfo.st_mode & ~S_IFMT;

			if ((curr_mode & adminsock_mode) != curr_mode) {
				plog(LLV_ERROR, LOCATION, NULL,
						"File does not have correct permissions. "
						"Expected : %d Has : %d\n",
						adminsock_mode, (curr_mode & S_IRWXU));
				goto out;
			}
			setracoonconf(conf_file_name);
			kill (getpid(), SIGHUP);
		}
		break;
	case ADMIN_REPLACE_SAINFO:
		{
			struct admin_com_replace_sainfo *ap_replace_sai = NULL;
			struct sainfo *old_sainfo = NULL, *new_sainfo = NULL;
			admin_com_addrinfo *src = NULL, *dst = NULL;
			struct sockaddr_in *temp_addr;
			vchar_t *s_id = NULL, *d_id = NULL, *p_id = NULL, *temp_id = NULL,
					*new_s_id = NULL, *new_d_id = NULL;
			int sa_count = 0;
			int remoteid = 0;
			int new_remoteid = 0;
			struct remoteconf *conf = NULL;  /// get the remoteid

			ap_replace_sai = (struct admin_com_replace_sainfo *)
				((caddr_t)com + sizeof(*com));

			s_id = get_ipsecdoi_id(&(ap_replace_sai->old_src_addr),
					IPSEC_ULPROTO_ANY);

			d_id = get_ipsecdoi_id(&(ap_replace_sai->old_dst_addr), IPSEC_ULPROTO_ANY);

			p_id = ipsecdoi_sockaddr2id((struct sockaddr *)&(ap_replace_sai->peeraddr),
					sizeof(struct in_addr),
					IPSEC_ULPROTO_ANY);
			ipsecdoi_idtype2doi(p_id);

			src = &(ap_replace_sai->new_src_addr);
			dst = &(ap_replace_sai->new_dst_addr);


			new_s_id = get_ipsecdoi_id(src, IPSEC_ULPROTO_ANY);
			new_d_id = get_ipsecdoi_id(dst, IPSEC_ULPROTO_ANY);


			temp_addr = (struct sockaddr_in *)&(ap_replace_sai->old_src_addr.addrt.addr);
			printf("Old src addr : %x\n",
					temp_addr->sin_addr.s_addr
				  );
			temp_addr = (struct sockaddr_in *)&(ap_replace_sai->old_dst_addr.addrt.addr);
			printf("Old dst addr : %x\n",
					temp_addr->sin_addr.s_addr
				  );

			temp_addr = (struct sockaddr_in *)&(ap_replace_sai->new_src_addr.addrt.addr);
			printf("New src addr : %x\n",
					temp_addr->sin_addr.s_addr
				  );

			temp_addr = (struct sockaddr_in *)&(ap_replace_sai->new_dst_addr.addrt.addr);
			printf("New dst addr : %x\n",
					temp_addr->sin_addr.s_addr
				  );

			/// how to get the remote addr?
			conf = getrmconf((struct sockaddr *)&(ap_replace_sai->old_dst_addr.addrt.addr));
			if (conf != NULL) {
				remoteid = conf->ph1id;
				plog(LLV_DEBUG, LOCATION, NULL, "Get remoteid success(%d).\n", remoteid);
			} else {
				plog(LLV_DEBUG, LOCATION, NULL, "Warning: no valid rmconf !\n");
				remoteid = 0;
			}

			/// how to get the remote addr?
			conf = getrmconf((struct sockaddr *)&(ap_replace_sai->new_dst_addr.addrt.addr));
			if (conf != NULL) {
				new_remoteid = conf->ph1id;
				plog(LLV_DEBUG, LOCATION, NULL, "Get new_remoteid success(%d).\n", remoteid);
			} else {
				plog(LLV_DEBUG, LOCATION, NULL, "Warning: no valid rmconf !\n");
				new_remoteid = 0;
			}

			do {
				sa_count++;
				// getsainfo(loc, rmt, peer, remoteid)
				old_sainfo = getsainfo(s_id, d_id, NULL, remoteid);

				if (old_sainfo && old_sainfo->idsrc){
					/* Corressponding Entry found.
					 * Allocate a new sa_info struct
					 * copy the new addresses
					 * delete the old one and insert the new one
					 */
					new_sainfo = dupsainfo(old_sainfo);
					if (new_sainfo == NULL) {
						plog(LLV_ERROR, LOCATION, NULL,
								"failed to allocate sainfo\n");
						if (sa_count == 2){
							/* Remove already added policy */
							new_sainfo =
								getsainfo(new_s_id, new_d_id, p_id, new_remoteid);
							if ((new_sainfo) &&
									(new_sainfo->idsrc != NULL)){
								/* Not an anonymous entry */
								remsainfo(new_sainfo);
								delsainfo(new_sainfo);
							}
						}
						goto out;
					}
					new_sainfo->idsrc = new_s_id;
					new_sainfo->iddst = new_d_id;

					inssainfo(new_sainfo);
					remsainfo(old_sainfo);
					delsainfo(old_sainfo);
				}
				else{
					/*
					   plog(LLV_ERROR, LOCATION, NULL,
					   "No matching sa_info found. Src(%s):Dst(%s)",
					   saddr2str((struct sockaddr *)&(src->addrt.addr)), saddr2str((struct sockaddr *)&(dst->addrt.addr)));
					   */
					plog(LLV_ERROR, LOCATION, NULL,
							"No matching sa_info found...\n");
					goto out;
				}

				//Repeat for the opposite direction
				temp_id = s_id;
				s_id = d_id;
				d_id = temp_id;

				temp_id = new_s_id;
				new_s_id = vdup(new_d_id);
				new_d_id = vdup(temp_id);

			} while (sa_count < 2);
		}
		break;
	case ADMIN_GET_VENDOR_PRIV_DATA:
		{
			caddr_t vendor_conf_opq_data = NULL;

			vendor_conf_opq_data = (caddr_t)com + sizeof(*com);
#ifdef PLUGINS_SUPPORT
			{
				size_t *gw_type_len = NULL;
				size_t *inbuf_len = NULL;
				int outbuf_len = 0;
				char gw_type[128];
				caddr_t inbuf = NULL, outbuf = NULL;
				caddr_t plugin_private_data = NULL;
				short *ver = NULL;

				/*
				 * The private data structure is as follows:
				 * Version +
				 * Gateway type in LV Format +
				 * Private data to be passed on to the IKE Plugin in LV Format
				 */

				/* Version */
				ver = (short *)vendor_conf_opq_data;
				vendor_conf_opq_data += sizeof(short);

				/* Gateway Type in LV format */
				gw_type_len = (size_t *)vendor_conf_opq_data;
				vendor_conf_opq_data += sizeof(size_t);

				memcpy(gw_type, (char *)vendor_conf_opq_data,
						*gw_type_len);
				gw_type[*gw_type_len] = '\0';
				vendor_conf_opq_data += *gw_type_len;

				/* Length of private data */
				inbuf_len = (size_t *)vendor_conf_opq_data;
				vendor_conf_opq_data += sizeof(size_t);
				inbuf = vendor_conf_opq_data;

				tpike_plugin_getdata(*ver, gw_type, *inbuf_len, inbuf,
						&outbuf_len, &outbuf);

				for (i = 0; i < sizeof(u_int32_t) * 2; i++)
					plog(LLV_DEBUG, LOCATION, NULL, "0x%2x ", *(((char *)outbuf) + i));
				plog(LLV_DEBUG, LOCATION, NULL, "\n");

				buf = vmalloc(outbuf_len);
				if (buf == NULL)
					com->ac_errno = -1;
				else
					memcpy(buf->v, outbuf, outbuf_len);

			}
#endif
		}
		break;
	case ADMIN_SET_VENDOR_CONFIG_DATA :
		{
			caddr_t vendor_conf_opq_data = NULL;

			vendor_conf_opq_data = (caddr_t)com + sizeof(*com);

#ifdef PLUGINS_SUPPORT
			{
				size_t *gw_type_len = NULL, *plugin_so_len = NULL;
				char plugin_so[256] = {'\0'}, gw_type[128] = {'\0'};
				caddr_t plugin_private_data = NULL;
				short *ver = NULL;
				/*
				 * The Private data structure is as follows:
				 * Version no(short) +
				 * Length of the Gateway type string(int) +
				 * Gateway type string (char *)+
				 * Length of Plugin so name string(int) +
				 * Name of the plugin so(char *) +
				 * Private Data to be passed on to the IKE plugin(void *)
				 */

				/* Get Version info */
				ver = (short *)vendor_conf_opq_data;
				vendor_conf_opq_data += sizeof(short);

				/* Gateway type in LV format */
				gw_type_len = (size_t *)vendor_conf_opq_data;
				vendor_conf_opq_data += sizeof(size_t);
				memcpy(gw_type, (char *)vendor_conf_opq_data, *gw_type_len);
				gw_type[*gw_type_len] = '\0';
				vendor_conf_opq_data += *gw_type_len;

				/* Plugin so name in  LV format */
				plugin_so_len = (size_t *)vendor_conf_opq_data;
				vendor_conf_opq_data += sizeof(size_t);
				memcpy(plugin_so, (char *)vendor_conf_opq_data, *plugin_so_len );
				plugin_so[*plugin_so_len] = '\0';
				vendor_conf_opq_data += *plugin_so_len;

				tpike_register_plugin(*ver,plugin_so,gw_type,vendor_conf_opq_data);
			}
#endif
		}
		break;
#endif

	default:
		plog(LLV_ERROR, LOCATION, NULL,
			"invalid command: %d\n", com->ac_cmd);
		com->ac_errno = -1;
	}

	if ((error = admin_reply(so2, com, buf)) != 0)
		goto out;

	error = 0;
out:
	if (buf != NULL)
		vfree(buf);

	return error;
}

static int
admin_reply(so, combuf, buf)
	int so;
	struct admin_com *combuf;
	vchar_t *buf;
{
	int tlen;
	char *retbuf = NULL;

	if (buf != NULL)
		tlen = sizeof(*combuf) + buf->l;
	else
		tlen = sizeof(*combuf);

	retbuf = racoon_calloc(1, tlen);
	if (retbuf == NULL) {
		plog(LLV_ERROR, LOCATION, NULL,
			"failed to allocate admin buffer\n");
		return -1;
	}

	memcpy(retbuf, combuf, sizeof(*combuf));
	((struct admin_com *)retbuf)->ac_len = tlen;

	if (buf != NULL)
		memcpy(retbuf + sizeof(*combuf), buf->v, buf->l);

	tlen = send(so, retbuf, tlen, 0);
	racoon_free(retbuf);
	if (tlen < 0) {
		plog(LLV_ERROR, LOCATION, NULL,
			"failed to send admin command: %s\n",
			strerror(errno));
		return -1;
	}

	return 0;
}

/* ADMIN_PROTO -> SADB_SATYPE */
int
admin2pfkey_proto(proto)
	u_int proto;
{
	switch (proto) {
	case ADMIN_PROTO_IPSEC:
		return SADB_SATYPE_UNSPEC;
	case ADMIN_PROTO_AH:
		return SADB_SATYPE_AH;
	case ADMIN_PROTO_ESP:
		return SADB_SATYPE_ESP;
	default:
		plog(LLV_ERROR, LOCATION, NULL,
			"unsupported proto for admin: %d\n", proto);
		return -1;
	}
	/*NOTREACHED*/
}

int
admin_init()
{
	if (adminsock_path == NULL) {
		lcconf->sock_admin = -1;
		return 0;
	}

	memset(&sunaddr, 0, sizeof(sunaddr));
	sunaddr.sun_family = AF_UNIX;
	snprintf(sunaddr.sun_path, sizeof(sunaddr.sun_path),
		"%s", adminsock_path);

	lcconf->sock_admin = socket(AF_UNIX, SOCK_STREAM, 0);
	if (lcconf->sock_admin == -1) {
		plog(LLV_ERROR, LOCATION, NULL,
			"socket: %s\n", strerror(errno));
		return -1;
	}

	unlink(sunaddr.sun_path);
	if (bind(lcconf->sock_admin, (struct sockaddr *)&sunaddr,
			sizeof(sunaddr)) != 0) {
		plog(LLV_ERROR, LOCATION, NULL,
			"bind(sockname:%s): %s\n",
			sunaddr.sun_path, strerror(errno));
		(void)close(lcconf->sock_admin);
		return -1;
	}

	if (chown(sunaddr.sun_path, adminsock_owner, adminsock_group) != 0) {
		plog(LLV_ERROR, LOCATION, NULL,
		    "chown(%s, %d, %d): %s\n",
		    sunaddr.sun_path, adminsock_owner,
		    adminsock_group, strerror(errno));
		(void)close(lcconf->sock_admin);
		return -1;
	}

	if (chmod(sunaddr.sun_path, adminsock_mode) != 0) {
		plog(LLV_ERROR, LOCATION, NULL,
		    "chmod(%s, 0%03o): %s\n",
		    sunaddr.sun_path, adminsock_mode, strerror(errno));
		(void)close(lcconf->sock_admin);
		return -1;
	}

	if (listen(lcconf->sock_admin, 5) != 0) {
		plog(LLV_ERROR, LOCATION, NULL,
			"listen(sockname:%s): %s\n",
			sunaddr.sun_path, strerror(errno));
		(void)close(lcconf->sock_admin);
		return -1;
	}
	plog(LLV_DEBUG, LOCATION, NULL,
		"open %s as racoon management.\n", sunaddr.sun_path);

	return 0;
}

int
admin_close()
{
	close(lcconf->sock_admin);
	return 0;
}

#ifdef ENABLE_AP_CLIENTMODE
int
add_policy_to_SPD(src_end_point, dst_end_point, policy)
	struct sockaddr_storage *src_end_point;
	struct sockaddr_storage *dst_end_point;
	struct admin_com_ph2policy *policy;
{
	char outpolicystr[POLICY_STR_LEN], inpolicystr[POLICY_STR_LEN];
	char *policyout = NULL, *policyin = NULL;
	char *local_ip_addr = NULL, *remote_ip_addr = NULL;

	struct sockaddr srcaddr;
	struct sockaddr dstaddr;
	struct sockaddr *addr = NULL;

	addr = (struct sockaddr *)src_end_point;
	local_ip_addr = strdup(saddrwop2str(addr));

	addr = (struct sockaddr *)dst_end_point;
	remote_ip_addr  = strdup(saddrwop2str(addr));

	/* end-points and policy for outbound trafic */
	switch(policy->action){
		case ACTION_ENCRYPT:
			sprintf(outpolicystr, "out ipsec %s/%s/%s-%s/unique",
					protocol[policy->protocol], mode[policy->mode],
					local_ip_addr,remote_ip_addr);
			sprintf(inpolicystr, "in ipsec %s/%s/%s-%s/unique",
					protocol[policy->protocol], mode[policy->mode],
					remote_ip_addr,local_ip_addr);
			break;
		case ACTION_BYPASS:
			sprintf(outpolicystr, "out none");
			sprintf(inpolicystr, "in none");
			break;
		case ACTION_DENY:
			sprintf(outpolicystr, "out discard");
			sprintf(inpolicystr, "in discard");
			break;
		default:
			plog(LLV_ERROR, LOCATION, NULL, "Unknown policy action\n");
	}
	/* set outbound policy */
	policyout = ipsec_set_policy(outpolicystr, strlen(outpolicystr));
	/* set inbound policy */
	policyin = ipsec_set_policy(inpolicystr, strlen(inpolicystr));

	racoon_free(local_ip_addr);
	racoon_free(remote_ip_addr);

	/* Add the policy to SPD */
	bzero(&srcaddr, sizeof(struct sockaddr));
	bzero(&dstaddr, sizeof(struct sockaddr));

	memcpy(&srcaddr, (struct sockaddr *)src_end_point,
			sizeof(struct sockaddr));
	memcpy(&dstaddr, (struct sockaddr *)&policy->dst_addr,
			sizeof(struct sockaddr));
	pfkey_add_policy_to_SPD(&srcaddr, 32, &dstaddr, policy->dst_prefixlen,
			policy->upperspec, policyin, policyout,0);
	return 0;
}
#endif
#endif

static void
isakmp_flush_sa(iph1, loc, rem)
	struct ph1handle *iph1;
	char *loc;
	char *rem;
{
	plog(LLV_INFO, LOCATION, NULL,
			"Flushing SA for %s -> %s\n", loc, rem);

	if (iph1->status == PHASE1ST_ESTABLISHED)
		isakmp_info_send_d1(iph1);

	remph1(iph1);
	delph1(iph1);

	return;
}

/*
 *     Temporary stuff being done for VPN Client for NLD
 *     IMPORTANT: To be removed as soon as the fix is available
 *     in gui plugin and plugin so
 */

//static LIST_HEAD(_ph1tree_, ph1handle) ph1tree;
extern LIST_HEAD(_ph1tree_, ph1handle) ph1tree;
int
add_default_policy_to_SPD(src_addr)
	int    src_addr;
{
	struct ph1handle *p = NULL;
	struct sockaddr srcaddr;
	struct sockaddr dstaddr;

	char outpolicystr[POLICY_STR_LEN], inpolicystr[POLICY_STR_LEN];
	char *policyout = NULL, *policyin = NULL;
	char *local_ip_addr = NULL, *remote_ip_addr = NULL;

	plog(LLV_INFO, LOCATION, NULL,
			"call add_default_policy_to_SPD(%08x).\n", src_addr);

	p = LIST_FIRST(&ph1tree);

	local_ip_addr = strdup(saddrwop2str(p->local));
	remote_ip_addr  = strdup(saddrwop2str(p->remote));

	/* end-points and policy for outbound trafic
	   Action is always ENCRYPT
	   */
#if 0
	sprintf(outpolicystr, "out ipsec esp/tunnel/%s-%s/unique",
			local_ip_addr,remote_ip_addr);
	sprintf(inpolicystr, "in ipsec esp/tunnel/%s-%s/unique",
			remote_ip_addr, local_ip_addr);
#else
	sprintf(outpolicystr, "out ipsec esp/tunnel/%s-%s/require",
			local_ip_addr,remote_ip_addr);
	sprintf(inpolicystr, "in ipsec esp/tunnel/%s-%s/require",
			remote_ip_addr, local_ip_addr);

#endif
	/* set outbound policy */
	policyout = ipsec_set_policy(outpolicystr, strlen(outpolicystr));
	/* set inbound policy */
	policyin = ipsec_set_policy(inpolicystr, strlen(inpolicystr));

	racoon_free(local_ip_addr);
	racoon_free(remote_ip_addr);

	/* Add the policy to SPD */
	bzero(&srcaddr, sizeof(struct sockaddr));
	bzero(&dstaddr, sizeof(struct sockaddr));

	((struct sockaddr_in  *)(&srcaddr))->sin_family = AF_INET;
	((struct sockaddr_in  *)(&srcaddr))->sin_addr.s_addr = (src_addr);

	((struct sockaddr_in  *)(&dstaddr))->sin_family = AF_INET;
	((struct sockaddr_in  *)(&dstaddr))->sin_addr.s_addr = INADDR_ANY;

	pfkey_add_policy_to_SPD(&srcaddr, 32, &dstaddr, 0/*policy->dst_prefixlen*/,
			0 , policyin, policyout,0);
	EVT_PUSH(0, 0, EVTT_ISAKMP_CFG_DONE, NULL);
	return 0;
}
