#ifndef __H_TPIKE_TYPES__
#define __H_TPIKE_TYPES__

enum tpike_auth_type {
   TPIKE_AUTH_TYPE_NONE = -1,
   TPIKE_AUTH_TYPE_XAUTH,
   TPIKE_AUTH_TYPE_X509
};

enum tpike_gateway_type {
   TPIKE_GATEWAY_TYPE_NONE = -1, 
   TPIKE_GATEWAY_TYPE_STDGW,
   TPIKE_GATEWAY_TYPE_NORTEL
#define TPIKE_GATEWAY_TYPE_MAX 2
};

#define ARRAYCOUNT(x) (sizeof ((x))/sizeof ((x)[0]))

#endif // __H_TPIKE_TYPES__
