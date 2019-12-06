#ifndef __H_UI_HELPERS__
#define __H_UI_HELPERS__

const gchar * ui_helper_get_dh_group ();
const gchar * ui_helper_get_pfs_group ();
const gchar * ui_helper_get_split_tunnel ();
void ui_helper_set_split_tunnel (const char const * flag);

enum tpike_auth_type ui_helper_get_authmethod ();
const gchar * ui_helper_get_authmethod_text ();
void ui_helper_set_authmethod (const char const * method);

enum tpike_gateway_type ui_helper_get_gateway_type ();
const gchar * ui_helper_get_gateway_type_text ();

const gchar * ui_helper_get_exchange_mode_text ();


#endif // __H_UI_HELPERS__
