/* mtu.c - Contains functions to get the mtu value for a given destination
 *
 * Authors:
 *          Vinay A R <rvinay@novell.com>
 * 
 * Based on work by Thomas Graf <tgraf@suug.ch> 
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 * $Id: mtu.c,v 1.1.2.3 2008/02/05 12:15:33 bili Exp $
 *
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <inttypes.h>
#include <errno.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netlink/netlink.h>
#include <netlink/cache.h>
#include <netlink/route/link.h>
#include <netlink/route/rtnl.h>
#include <netlink/route/route.h>

static unsigned int mtu = 0;

static struct nla_policy route_policy[RTA_MAX+1] = {
	[RTA_IIF]	= { .type = NLA_STRING,
			    .maxlen = IFNAMSIZ, },
	[RTA_OIF]	= { .type = NLA_U32 },
	[RTA_PRIORITY]	= { .type = NLA_U32 },
	[RTA_FLOW]	= { .type = NLA_U32 },
	[RTA_MP_ALGO]	= { .type = NLA_U32 },
	[RTA_CACHEINFO]	= { .minlen = sizeof(struct rta_cacheinfo) },
	[RTA_METRICS]	= { .type = NLA_NESTED },
	[RTA_MULTIPATH]	= { .type = NLA_NESTED },
};

int route_msg_parser(struct nl_msg *msg, void *arg)
/*int route_msg_parser(struct sockaddr_nl *who, struct nlmsghdr *n,
			    void *arg)*/
{
	struct nlattr *tb[RTA_MAX + 1];
	struct nlmsghdr *n = nlmsg_hdr(msg);
	struct rtmsg *r = nlmsg_data(n);
	int err;
	uint32_t m;

	err = nlmsg_parse(n, sizeof(*r), tb, RTA_MAX, route_policy);
	if (err < 0)
		return err;

	if (tb[RTA_METRICS]) {
		struct nlattr *mtb[RTAX_MAX + 1];

		err = nla_parse_nested(mtb, RTAX_MAX, tb[RTA_METRICS], NULL);
		if (err < 0)
			return err ;

		m = nla_get_u32(mtb[RTAX_MTU]);
		mtu = m;
	}
	return 0;
}

int get_mtu(const char *dest_str)
{
	struct nl_handle *nlh;
	struct nl_cache *link_cache, *route_cache;
	struct nl_addr *dst;
	struct nl_cb *callback = NULL;

	callback = nl_cb_alloc(NL_CB_VERBOSE);
	if (!callback)
		goto errout;

	nlh = nl_handle_alloc_cb(callback);
	//nlh = nl_handle_alloc_nondefault(NL_CB_VERBOSE);
	if (!nlh)
		goto errout;

	if (nl_connect(nlh, NETLINK_ROUTE) < 0)
		goto errout_free_handle;

	link_cache = rtnl_link_alloc_cache(nlh);
	if (!link_cache)
		goto errout_close;

	dst = nl_addr_parse(dest_str, AF_UNSPEC);
	if (!dst)
		goto errout_link_cache;

	route_cache = rtnl_route_alloc_cache(nlh);
	if (!route_cache)
		goto errout_addr_put;

	{
		struct nl_msg *m;
		struct rtmsg rmsg = {
			.rtm_family = nl_addr_get_family(dst),
			.rtm_dst_len = nl_addr_get_prefixlen(dst),
		};

		m = nlmsg_build_simple(RTM_GETROUTE, 0);
		nlmsg_append(m, &rmsg, sizeof(rmsg), 1);
		nla_put_addr(m, RTA_DST, dst);

		//if ((nl_send_auto_complete(nlh, nlmsg_hdr(m))) < 0) {
		if ((nl_send_auto_complete(nlh, m)) < 0) {
			nlmsg_free(m);
			fprintf(stderr, "%s\n", nl_geterror());
		goto errout_route_cache;
		}

		nlmsg_free(m);

		//nl_cb_set(nl_handle_get_cb(nlh), NL_CB_VALID, NL_CB_CUSTOM,
		nl_cb_set(callback, NL_CB_VALID, NL_CB_CUSTOM,
			  route_msg_parser, route_cache);

                if (nl_recvmsgs_def(nlh) < 0) {
                          fprintf(stderr, "%s\n", nl_geterror());
                          goto errout_route_cache;
                 }
	}

errout_route_cache:
	//nl_cache_destroy_and_free(route_cache);
	nl_cache_free(route_cache);
errout_addr_put:
	nl_addr_put(dst);
errout_link_cache:
	//nl_cache_destroy_and_free(link_cache);
	nl_cache_free(link_cache);
errout_close:
	nl_close(nlh);
errout_free_handle:
	nl_handle_destroy(nlh);
errout:
	return mtu;
}
