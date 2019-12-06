#include<stdio.h>
#include<stdlib.h>
 
 			#ifdef ENABLE_NLS
 			#  include <libintl.h>
 			#  undef _ 
 			#  define _(String) dgettext (PACKAGE, String) 
 			#  ifdef gettext_noop 
 			#    define N_(String) gettext_noop (String) 
 			#  else 
 			#    define N_(String) (String) 
 			#  endif 
 			#else 
 			#  define textdomain(String) (String) 
 			#  define gettext(String) (String) 
 			#  define dgettext(Domain,Message) (Message) 
 			#  define dcgettext(Domain,Message,Type) (Message)
 			#  define bindtextdomain(Domain,Directory) (Domain)
 			#  define _(String) (String)
 			#  define N_(String) (String)
 			#endif
 						#define PACKAGE "turnpike" 
  			
 char * _errString(int errorNo)
 { 
	 switch(errorNo) {
		case 0x0100: 
			return _("IKE Phase 1 established");
		case 0x0101: 
			return _("IKE Phase 1 deleted");
		case 0x0102: 
			return _("Xauth exchange successful");
		case 0x0103: 
			return _("ISAKMP mode config successful");
		case 0x0104: 
			return _("IKE Phase 2 established");
		case 0x0105: 
			return _("IKE Phase 2 deleted");
		case 0x0106: 
			return _("IKE Peer is not reachable");
		case 0x0107: 
			return _("IKE Peer is not responding");
		case 0x0108: 
			return _("IKE Peer terminated security association");
		case 0x0109: 
			return _("Raccon terminated");
		case 0x010A: 
			return _("Event queue overflow");
		case 0x0110: 
			return _("Xauth exchange failed");
		case 0x0111: 
			return _("IKE Phase 1 authentication failed.");
		case 0x1100: 
			return _("Certificate not found. Ensure that the certificate is available.");
		case 0x1101: 
			return _("Certificate not found. Ensure that the certificate is available.");
		case 0x1102: 
			return _("Enter gateway name/IP address.");
		case 0x1103: 
			return _("The certificate name is too lengthy. Rename the Certificate name to proceed.");
		case 0x1104: 
			return _("Enter the password.");
		case 0x1105: 
			return _("certificate error has occurred. Verify your certificate.");
		case 0x1106: 
			return _("Certificate not found. Ensure that the certificate is available.");
		case 0x1107: 
			return _("Certificate directory does not exit");
		case 0x1108: 
			return _("Failed to read certificate. Either the certificate is invalid or the password is not correct.");
		case 0x1109: 
			return _("Gateway name/IP address is not valid");
		case 0x110A: 
			return _("Gateway IP address is not valid");
		case 0x110B: 
			return _("Server address error: Failed to resolve the DNS name. Retry after some time.");
		case 0x110C: 
			return _("Could not read profile. Recreate the profile. ");
		case 0x110D: 
			return _("Profile is not valid.");
		case 0x110E: 
			return _("Failed to connect to IKE. Restart IKE.");
		case 0x110F: 
			return _("Failed to connect to IKE. Restart IKE.");
		case 0x1110: 
			return _("Failed to connect to IKE. Restart IKE.");
		case 0x1111: 
			return _("Failed to connect to IKE. Restart IKE.");
		case 0x1112: 
			return _("IKE failed to respond. The client is exiting.\n");
		case 0x1113: 
			return _("Gateway name/IP address is not valid.");
		case 0x1114: 
			return _("Failed to meet system requirements. Gmodule support is not available.");
		case 0x1115: 
			return _("Unable to locate the Help file. Reinstall the client.");
		case 0x1116: 
			return _("Profiles directory does not exist. Client installation might be incomplete.");
		case 0x1117: 
			return _("Invalid Network. Re-enter");
		case 0x1118: 
			return _("Invalid Mask. Re-enter");
		case 0x1119: 
			return _("Timeout occured while waiting for a connection response from gateway. The client is exiting.\n");
		case 0x1120: 
			return _("Profile name is blank. Enter profile name.");
		case 0x1121: 
			return _("Invalid authentication details for profile creation. Please check.");
		case 0x1122: 
			return _("Authentication failed. Verify your credentials.");
		case 0x1123: 
			return _("Gateway not responding. The client is exiting.\n");
		case 0x1200: 
			return _("Can not open the file %s for editing\n");
		case 0x1201: 
			return _("Gateway name/IP address %s is not valid\n");
		case 0x1202: 
			return _("Failed to connect to IKE. Restart IKE.\n");
		case 0x1203: 
			return _("Failed to connect to the Gateway.\n");
		case 0x1204: 
			return _("Can not read the profile %s\n");
		case 0x1205: 
			return _("Profile  %s is not valid\n");
		case 0x1206: 
			return _("Profile directory %s does not exist \n");
		case 0x1207: 
			return _("Failed to set user Environment. The client is exiting \n");
		case 0x1208: 
			return _("Profie  %s not found\n");
		case 0x1209: 
			return _("Too many arguments\n");
		case 0x120A: 
			return _("Verbose Mode has no meaning when specified alone\n");
		case 0x120B: 
			return _("Profile %s does not exist\n");
		case 0x120C: 
			return _("Certificate path %s does not exist\n");
		case 0x120D: 
			return _("Failed to extract certificate. Either the certificate is invalid or the password is not correct\n");
		case 0x120E: 
			return _("Failed to connect to the gateway \n");
		case 0x120F: 
			return _("Plugin %s is not compatible\n");
		case 0x1210: 
			return _("Gateway IP Address is invalid \n");
		case 0x1211: 
			return _("DNS Resolution failed for gateway address specified in the profile\n");
		case 0x1212: 
			return _("Timeout occured while waiting for a connection response from gateway.The client is exiting\n");
		case 0x1213: 
			return _("Profile does not exist. Create the profile using the GUI\n");
		case 0x1214: 
			return _("Authentication failed. Verify your credentials.\n");
		case 0x1215: 
			return _("Peer disconnected due to inactivity .\n");
		default : 
			return ("no error code is matched");
	}
}
