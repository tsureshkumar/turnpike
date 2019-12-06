/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/***************************************************************************
 *
 * Copyright (C) 2009 Bin Li, <bili@novell.com>
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
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 **************************************************************************/

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <string.h>
#include <sys/types.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <ctype.h>

#include <libxml/tree.h>

#include <glib/gi18n-lib.h>

#include <nm-setting-vpn.h>
#include <nm-setting-connection.h>
#include <nm-setting-ip4-config.h>

#include "import-export.h"
#include "nm-novellvpn.h"
#include "../src/nm-novellvpn-service.h"

#define VENDOR_TAG         "vendor"
#define GATEWAY_IP_TAG     "gateway_ip"
#define GATEWAY_TYPE_TAG   "gateway_type"
#define CERTIFICATE_TAG    "certificate"
#define POLICIES_TAG       "policies"
#define PHASE1_TAG         "phase1"
#define PHASE2_TAG         "phase2"
#define DHGROUP_TAG        "dhgroup"
#define PFSGROUP_TAG       "pfsgroup"
#define AUTHMETHOD_TAG     "authmethod"
#define PHASE_CONFIG_TAG   "phase_config"
#define ENTRY_TAG          "entry"
#define PROPOSALS_TAG      "proposals"
#define NOSPLITTUNNEL_TAG  "nosplittunnel"

static int parse_vendor_prf (
		const char *profilename,
		NMSettingVPN *s_vpn,
		GError **error)
{
	xmlNode *cur_node = NULL;
	xmlChar *buffer = NULL;
	xmlDocPtr doc;
	xmlNode *root = NULL;

	doc = xmlParseFile(profilename);
	if (doc == NULL) {
		g_warning ("parse the profile %s failed!", profilename);
		return -1;
	}

	/* Get the root element node */
	root = xmlDocGetRootElement(doc);
	if( !root || !root->name || xmlStrcmp (root->name, (const xmlChar *)VENDOR_TAG)) {
		g_warning ("the vendor profile %s is bad!", profilename);
		xmlFreeDoc(doc);
		return -1;
	}

	/* Find the name */
	for (cur_node = root; cur_node != NULL; cur_node = cur_node->next) {
		if (cur_node->type == XML_ELEMENT_NODE
				&& !xmlStrcmp (cur_node->name, (const xmlChar *)VENDOR_TAG)) {

			buffer= xmlGetProp (cur_node, (const xmlChar *)"vendorname");
			if (buffer) {
				xmlFree (buffer);
				buffer = NULL;
			}
		}
	}

	for (cur_node = root->children; cur_node != NULL; cur_node = cur_node->next) {
		if (cur_node->type != XML_ELEMENT_NODE)
			continue;

		if (strcmp ((const char*)cur_node->name, "groupname") == 0) {
			buffer = xmlNodeGetContent (cur_node);
			if (buffer) {
				if (strlen ((char *)buffer)) {
					nm_setting_vpn_add_data_item (s_vpn,
							NM_NOVELLVPN_KEY_GROUP_NAME,
							(char *)buffer);
				}
				xmlFree (buffer);
				buffer = NULL;
			}

		} else if (strcmp ((const char*)cur_node->name, "gatewayip") == 0) {
		} else if (strcmp ((const char*)cur_node->name, "grouppasswd") == 0) {
			buffer = xmlNodeGetContent(cur_node);
			if (buffer) {
				if (strlen ((char *)buffer)) {
					// the grouppasswd is encrypt
					nm_setting_vpn_add_secret (s_vpn,
							NM_NOVELLVPN_KEY_ENC_GRP_PWD,
							(char *)buffer);
				}
				xmlFree (buffer);
				buffer = NULL;
			}
		} else if (strcmp ((const char*)cur_node->name, "username") == 0) {
			buffer = xmlNodeGetContent(cur_node);
			if (buffer) {
				if (strlen ((char *)buffer)) {
					nm_setting_vpn_add_data_item (s_vpn,
							NM_NOVELLVPN_KEY_USER_NAME,
							(char *)buffer);
				}
				xmlFree (buffer);
				buffer = NULL;
			}
		}
	}

	return 0;
}

static int parse_policies (
		xmlNode *phasenode,
	   	NMSettingVPN *s_vpn,
	   	GError **error)
{
	xmlNode *cur_node = NULL;
	xmlNode *prop_node = NULL;
	xmlNode *entry_node = NULL;
	xmlChar *buffer = NULL;

	for (cur_node = phasenode; cur_node != NULL; cur_node = cur_node->next) {

		if (cur_node->type != XML_ELEMENT_NODE)
			continue;

		if (strcmp ((const char *)cur_node->name, PHASE1_TAG) == 0) {

			for (prop_node = cur_node->children;
				   	prop_node != NULL; prop_node = prop_node->next) {

				if (prop_node->type != XML_ELEMENT_NODE)
					continue;

				if (strcmp ((const char*)prop_node->name, PROPOSALS_TAG) == 0) {

					for (entry_node = prop_node->children;
						   	entry_node != NULL; entry_node = entry_node->next) {

						if (entry_node->type != XML_ELEMENT_NODE)
							continue;

						if (strcmp ((const char *)entry_node->name, ENTRY_TAG) == 0) {

							buffer= xmlGetProp (entry_node, (const xmlChar*)DHGROUP_TAG);
							if (buffer) {
								if (strlen ((char *)buffer)) {
									if (strcmp ((char *)buffer, "dh1") == 0) {
										nm_setting_vpn_add_data_item (s_vpn,
												NM_NOVELLVPN_KEY_DHGROUP,
												"0");
									} else if (strcmp ((char *)buffer, "dh2") == 0) {
										nm_setting_vpn_add_data_item (s_vpn,
												NM_NOVELLVPN_KEY_DHGROUP,
												"1");
									} else {
										// bad value
										g_warning ("dhgroup in file is a bad value\n");
									}
								}
								xmlFree (buffer);
								buffer = NULL;
							}

							buffer= xmlGetProp (entry_node, (const xmlChar*)AUTHMETHOD_TAG);
							if (buffer) {
								if (strlen ((char *)buffer)) {
									// in the older turnpike the "PSK" is same to "XAUTH"
									if (strcmp ((char *)buffer, "PSK") == 0) {
										nm_setting_vpn_add_data_item (s_vpn,
												NM_NOVELLVPN_KEY_AUTHTYPE,
												NM_NOVELLVPN_CONTYPE_GROUPAUTH_STRING);
									} else if (strcmp ((char *)buffer, "X.509") == 0) {
										nm_setting_vpn_add_data_item (s_vpn,
												NM_NOVELLVPN_KEY_AUTHTYPE,
												NM_NOVELLVPN_CONTYPE_X509_STRING);
									} else {
										// bad value
										g_warning ("authtype in file is a bad value\n");
									}
								}
								xmlFree (buffer);
								buffer = NULL;
							}
						}
					}
				}
			}
		} else if (strcmp ((const char *)cur_node->name, PHASE_CONFIG_TAG) == 0) {

			for (entry_node = cur_node->children;
					entry_node != NULL; entry_node = entry_node->next) {

				if (entry_node->type != XML_ELEMENT_NODE)
					continue;

				if (strcmp ((const char *)entry_node->name, ENTRY_TAG) == 0) {

					buffer= xmlGetProp (entry_node, (const xmlChar*)NOSPLITTUNNEL_TAG);
					if (buffer) {
						if (strlen ((char *)buffer)) {
							if (strcmp ((char *)buffer, "no") == 0
									|| strcmp ((char *)buffer, "yes") == 0) {
								nm_setting_vpn_add_data_item (s_vpn,
										NM_NOVELLVPN_KEY_NOSPLITTUNNEL,
										(char *)buffer);
							} else {
								// some bad value for pfsgroup
								g_warning ("unknown nosplittunnel option '%s'\n", buffer);
							}
						}
						xmlFree (buffer);
						buffer = NULL;
					}
				}
			}
		} else if (strcmp ((const char *)cur_node->name, PHASE2_TAG) == 0) {
			for (prop_node = cur_node->children;
				   	prop_node != NULL; prop_node = prop_node->next) {

				if (prop_node->type != XML_ELEMENT_NODE)
					continue;

				if (strcmp ((const char*)prop_node->name, PROPOSALS_TAG) == 0) {

					for (entry_node = prop_node->children;
						   	entry_node != NULL; entry_node = entry_node->next) {

						if (entry_node->type != XML_ELEMENT_NODE)
							continue;

						if (strcmp ((const char *)entry_node->name, ENTRY_TAG) == 0) {

							buffer= xmlGetProp (entry_node, (const xmlChar*)PFSGROUP_TAG);
							if (buffer) {
								if (strlen ((char *)buffer)) {
									if (strcmp ((char *)buffer, "off") == 0) {
										nm_setting_vpn_add_data_item (s_vpn,
												NM_NOVELLVPN_KEY_PFSGROUP,
												"0");
									} else if (strcmp ((char *)buffer, "1") == 0
											|| strcmp ((char *)buffer, "2") == 0) {
										nm_setting_vpn_add_data_item (s_vpn,
												NM_NOVELLVPN_KEY_PFSGROUP,
												(char *)buffer);
									} else {
										// some bad value for pfsgroup
										g_warning ("unknown psfgroup option '%s'\n", buffer);
									}
								}
								xmlFree (buffer);
								buffer = NULL;
							}
						}
					}
				}
			}
		}
	}

	return 0;
}

static int parse_prf (const char *profilename, NMSettingVPN *s_vpn, GError **error)
{
	xmlNode *cur_node;
	xmlChar *buffer = NULL;
	xmlDocPtr doc;
	xmlNode *root = NULL;

	doc = xmlParseFile (profilename);
	if (doc == NULL) {
		g_warning ("parse the profile %s failed!", profilename);
		return -1;
	}

	/* Get the root element node */
	root = xmlDocGetRootElement (doc);
	if( !root || !root->name
		   	|| xmlStrcmp (root->name,(const xmlChar *)"profile")) {
		g_warning ("the profile %s is bad!", profilename);
		xmlFreeDoc (doc);
		return -1;
	}

	/* Find the name */
	for (cur_node = root; cur_node != NULL; cur_node = cur_node->next) {
		if (cur_node->type == XML_ELEMENT_NODE
				&& !xmlStrcmp (cur_node->name, (const xmlChar *)"profile")) {

			buffer= xmlGetProp (cur_node, (const xmlChar *)"name");
			if (buffer) {
				xmlFree (buffer);
				buffer = NULL;
			}
		}
	}

	for (cur_node = root->children; cur_node != NULL; cur_node = cur_node->next) {
		if (cur_node->type != XML_ELEMENT_NODE)
			continue;

		if (strcmp ((const char*)cur_node->name, VENDOR_TAG) == 0) {
			buffer = xmlNodeGetContent (cur_node);
			if (buffer) {
				if (strlen ((char *)buffer)) {
					char *path = NULL;
					char vendorfile[255] = {0};

					path = g_path_get_dirname (profilename);
					snprintf (vendorfile, 255, "%s/%s",
							path, buffer);
					g_free (path);
					// Parse the vendor file to get group name and username
					parse_vendor_prf (vendorfile, s_vpn, error);
				}
				xmlFree (buffer);
				buffer = NULL;
			}
		} else if (strcmp ((const char*)cur_node->name, GATEWAY_IP_TAG) == 0) {

			buffer = xmlNodeGetContent(cur_node);
			if (buffer) {
				if (strlen ((char *)buffer)) {
					nm_setting_vpn_add_data_item (s_vpn,
							NM_NOVELLVPN_KEY_GATEWAY,
							(char *)buffer);
				}
				xmlFree (buffer);
				buffer = NULL;
			}

		} else if (strcmp ((const char*)cur_node->name, GATEWAY_TYPE_TAG) == 0) {

			char *gwtype = NULL;

			buffer = xmlNodeGetContent (cur_node);
			if (buffer) {
				if (strlen ((char *)buffer)) {
					if (strcmp ((char *)buffer, "Standard IPsec gateway") == 0) {
						gwtype = NM_NOVELLVPN_GWTYPE_STDGW_STRING;
					} else {
						gwtype = NM_NOVELLVPN_GWTYPE_NORTEL_STRING;
					}
					nm_setting_vpn_add_data_item (s_vpn,
							NM_NOVELLVPN_KEY_GWTYPE,
							gwtype);
				}
				xmlFree (buffer);
				buffer = NULL;
			}
		} else if (strcmp ((const char*)cur_node->name, CERTIFICATE_TAG) == 0) {
			buffer = xmlNodeGetContent (cur_node);
			if (buffer) {
				if (strlen ((char *)buffer)) {
					nm_setting_vpn_add_data_item (s_vpn,
							NM_NOVELLVPN_KEY_CERTIFICATE,
							(char *)buffer);
				}
				xmlFree (buffer);
				buffer = NULL;
			}
		} else if (strcmp ((const char*)cur_node->name, POLICIES_TAG) == 0) {
			parse_policies (cur_node->children, s_vpn, error);
		}
	}

	xmlCleanupGlobals ();
	xmlCleanupParser ();
	xmlFreeDoc (doc);

	return 0;
}
/*
 * import the turnpike's profile, usually in ~/.turnpike/profiles/
 * if you wanna get the username and groupname,
 * you need provide the vendor profiles  in ~/.turnpike/vendorprofiles/
 * copy these two file out to the same directory, the import will load
 * them automatically.
 */
NMConnection *
do_import (const char *path, GError **error)
{
	NMConnection *connection = NULL;
	NMSettingConnection *s_con = NULL;
	NMSettingVPN *s_vpn = NULL;
	char *last_dot = NULL;
	char *basename = NULL;
	int ret = 0;

	connection = nm_connection_new ();
	s_con = NM_SETTING_CONNECTION (nm_setting_connection_new ());
	nm_connection_add_setting (connection, NM_SETTING (s_con));

	s_vpn = NM_SETTING_VPN (nm_setting_vpn_new ());
	g_object_set (s_vpn, NM_SETTING_VPN_SERVICE_TYPE,
		   	NM_DBUS_SERVICE_NOVELLVPN, NULL);


	basename = g_path_get_basename (path);
	last_dot = strrchr (basename, '.');
	if (last_dot)
		*last_dot = '\0';

	g_object_set (s_con, NM_SETTING_CONNECTION_ID, basename, NULL);
	g_free (basename);

	ret = parse_prf (path, s_vpn, error);
	if (ret < 0) {
		g_set_error (error,
				NOVELLVPN_PLUGIN_UI_ERROR,
				NOVELLVPN_PLUGIN_UI_ERROR_FILE_NOT_NOVELLVPN,
				"The file to import wasn't a valid NovellVPN client configuration.");
		g_object_unref (connection);
		connection = NULL;
	}

	nm_connection_add_setting (connection, NM_SETTING (s_vpn));

	return connection;
}

static
int is_file_exist (const char *filename)
{
	struct stat buf;

	if (lstat (filename,&buf)<0)
		return -1;

	else if (!S_ISREG(buf.st_mode) || (buf.st_size==0))
		return -1;

	return 0;
}

static void export_vendor (const char *path, NMSettingVPN *s_vpn)
{
	xmlDocPtr doc;
	xmlNodePtr root_node = NULL;
	xmlNode *root = NULL;
	xmlNodePtr childptr = NULL;
	const char *value = NULL;

	if (!is_file_exist(path)) //Remove and rewrite it 
		remove(path);

	doc = xmlNewDoc (BAD_CAST "1.0");
	root_node = xmlNewNode (NULL, BAD_CAST "vendor");
	xmlDocSetRootElement (doc, root_node);

	root = xmlDocGetRootElement (doc);
	xmlNewProp (root, (const xmlChar *)"vendorname", (const xmlChar *)"nortel");

	value = nm_setting_vpn_get_data_item (s_vpn, NM_NOVELLVPN_KEY_GROUP_NAME);
	if (value && strlen (value)) {
		childptr = xmlNewTextChild (root,
				NULL,
				(const xmlChar *) "groupname",
				(const xmlChar *) value);
	}

    value = nm_setting_vpn_get_data_item (s_vpn, NM_NOVELLVPN_KEY_GATEWAY);
	if (value && strlen (value)) {
		childptr = xmlNewTextChild (root,
				NULL,
				(const xmlChar *) "gatewayip",
				(const xmlChar *) value);
	}

	childptr = xmlNewTextChild (root,
		   	NULL,
		   	(const xmlChar *) "grouppasswd",
		   	(const xmlChar *) "");

	xmlKeepBlanksDefault (0);
	xmlSaveFormatFile (path, doc, 1);
	xmlFreeDoc (doc);
}

/*
 * do_export export the turnpike profile for nvpn and vpnlogin.
 * the profile name would be profile_xxx.prf and if you use the
 * nortel gateway, it also export the vendor_xxx.prf
 * put the profile_xxx.prf in ~/.turnpike/profiles and the
 * vendor_xxx.prf in ~/.turnpike/vendorprofiles, then use the
 * vpnlogin to set the group password, after that you can use
 * the nvpn and vpnlogin to connect the Server.
 */
gboolean
do_export (const char *path, NMConnection *connection, GError **error)
{
	NMSettingVPN *s_vpn = NULL;
	const char *value = NULL;
	xmlNodePtr childptr = NULL, policyptr = NULL;
    xmlNodePtr proposalptr = NULL, entryptr = NULL;
	xmlNodePtr root_node = NULL;
	xmlDocPtr doc;
	xmlNode *root = NULL;
	char *authtype = NULL;
	char profile_name[255] = {0};
	char vendor_filename[255] = {0};
	char *basename = NULL;
	char *tmp = NULL;
	gboolean ret = FALSE;

	s_vpn = NM_SETTING_VPN (nm_connection_get_setting (
			connection, NM_TYPE_SETTING_VPN));
	if (s_vpn == NULL) {
		g_set_error (error,
				NOVELLVPN_PLUGIN_UI_ERROR,
				NOVELLVPN_PLUGIN_UI_ERROR_INVALID_CONNECTION,
				"couldn't connection vpn settting");
		return FALSE;
	}

	doc = xmlNewDoc (BAD_CAST "1.0");
	root_node = xmlNewNode (NULL, BAD_CAST "profile");
	xmlDocSetRootElement (doc, root_node);

	root = xmlDocGetRootElement (doc);

	// dismiss the prefix of name
	basename = g_path_get_basename (path);
	if (basename) {
		if (strstr (basename, "profile_") != NULL)
			strcpy (profile_name, basename + strlen ("profile_"));
		else
			strcpy (profile_name, basename);

		g_free (basename);
	}

	//dismiss the ext name
	tmp = strrchr (profile_name, '.');
	if (tmp)
		*tmp = '\0';

	xmlNewProp (root, (const xmlChar *)"name", (const xmlChar *) profile_name);

	sprintf (vendor_filename, "vendor_%s.prf", profile_name);

	childptr = xmlNewTextChild (root,
			NULL,
			(const xmlChar *)VENDOR_TAG,
			(const xmlChar *)vendor_filename);

	value = nm_setting_vpn_get_data_item (s_vpn, NM_NOVELLVPN_KEY_GATEWAY);
	if (value && strlen (value)) {
		childptr = xmlNewTextChild (root,
			   	NULL,
				(const xmlChar *)GATEWAY_IP_TAG,
			   	(const xmlChar *)value);
	} else {
		g_set_error (error, 0, 0, "connection was incomplete (missing gateway)");
		goto done;
	}

	value = nm_setting_vpn_get_data_item (s_vpn, NM_NOVELLVPN_KEY_GWTYPE);
	if (value && strlen (value)) {
		if (0 == strncmp (value, NM_NOVELLVPN_GWTYPE_NORTEL_STRING,
					strlen (NM_NOVELLVPN_GWTYPE_NORTEL_STRING))) {
			childptr = xmlNewTextChild (root,
					NULL,
					(const xmlChar *)GATEWAY_TYPE_TAG,
					(const xmlChar *)"nortel");

			// when the gateway type is nortel write the vendor file
			char *tmp = g_path_get_dirname (path);
			if (tmp) {
				sprintf (vendor_filename, "%s/vendor_%s.prf", tmp, profile_name);
				g_free (tmp);
			}

			export_vendor (vendor_filename, s_vpn);
		} else
			childptr = xmlNewTextChild (root,
					NULL,
					(const xmlChar *)GATEWAY_TYPE_TAG,
					(const xmlChar *)"Standard IPsec gateway");
	} else {
		g_set_error (error, 0, 0,
			   	"connection was incomplete (missing gateway type)");
		goto done;
	}

	value = nm_setting_vpn_get_data_item (s_vpn, NM_NOVELLVPN_KEY_AUTHTYPE);
	if (value && strlen (value)) {
		if (0 == strncmp (value, NM_NOVELLVPN_CONTYPE_GROUPAUTH_STRING,
					strlen (NM_NOVELLVPN_CONTYPE_GROUPAUTH_STRING)))
			authtype = "PSK";
		else
			authtype = "X.509";
	}

	value = nm_setting_vpn_get_data_item (s_vpn, NM_NOVELLVPN_KEY_CERTIFICATE);
	if (value && strlen (value)) {
		// when the authtype is "X.509", add the cert file
		if (0 == strncmp (authtype, "X.509", strlen("X.509")))
			childptr = xmlNewTextChild (root,
					NULL,
					(const xmlChar *)"certificate",
					(const xmlChar *)value);
	}

	policyptr = xmlNewChild (root, NULL, (const xmlChar *)"policies", NULL);

	childptr = xmlNewChild (policyptr, NULL, (const xmlChar *)"phase1", NULL);
	proposalptr = xmlNewChild (childptr, NULL, (const xmlChar *)"proposals", NULL);
	entryptr = xmlNewChild (proposalptr, NULL, (const xmlChar *)"entry", NULL);

	xmlNewProp (entryptr,
			(const xmlChar *)"mode",
			(const xmlChar*)"AM"); // "AM" or "MM"

	value = nm_setting_vpn_get_data_item (s_vpn, NM_NOVELLVPN_KEY_DHGROUP);
	if (value && strlen (value)) {
		if (strncmp (value, "1", 1) == 0)
			xmlNewProp (entryptr,
					(const xmlChar *)"dhgroup",
					(const xmlChar *)"dh2");
		else
			xmlNewProp (entryptr,
					(const xmlChar *)"dhgroup",
					(const xmlChar *)"dh1");
	}

	xmlNewProp (entryptr,
			(const xmlChar *)"authmethod",
			(const xmlChar *)authtype); // XAUTH or X.509

	/* Cause the config mode between phase1 and phase2, we used phase15 */
	childptr = xmlNewChild (policyptr,
			NULL,
			(const xmlChar *)"phase_config",
			NULL);
	entryptr = xmlNewChild (childptr,
			NULL,
			(const xmlChar *)"entry",
			NULL);

	value = nm_setting_vpn_get_data_item (s_vpn, NM_NOVELLVPN_KEY_NOSPLITTUNNEL);
	if (value && strlen (value)) {
		xmlNewProp (entryptr,
				(const xmlChar *)"nosplittunnel",
				(const xmlChar *)value);
	}

	childptr = xmlNewChild (policyptr,
			NULL,
			(const xmlChar *)"phase2",
			NULL);
	proposalptr = xmlNewChild (childptr,
			NULL,
			(const xmlChar *)"proposals",
		   	NULL);

	entryptr = xmlNewChild (proposalptr,
			NULL,
			(const xmlChar *)"entry",
		   	NULL);

	value = nm_setting_vpn_get_data_item (s_vpn, NM_NOVELLVPN_KEY_PFSGROUP);
	if (value && strlen (value)) {
		if (0 == strncmp (value, "0", 1))
			xmlNewProp (entryptr,
					(const xmlChar *)"pfsgroup",
					(const xmlChar *)"off");
		else
			xmlNewProp (entryptr,
					(const xmlChar *)"pfsgroup",
					(const xmlChar *)value);
	}

	ret = TRUE;

done:
	xmlKeepBlanksDefault (0);
	xmlSaveFormatFile (path, doc, 1);
	xmlFreeDoc (doc);

	return ret;
}
