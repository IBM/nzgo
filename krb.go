// +build kerberos

package nzgo

import (
	"strings"
	"unsafe"
)

/*

#include <krb5.h>
#include <stdlib.h>
struct go_krb5_info
{
   krb5_context go_krb5_context;
   krb5_ccache go_krb5_ccache;
   krb5_principal go_krb5_client;
}info;

krb5_principal server;
char *go_krb5_name;
krb5_error *err_ret;
krb5_auth_context auth_context;
*/
import "C"

// this is default krb service name
const GO_KRB_SRVNAM = "netezza"

func (cn *conn) go_krb5_sendauth(hostname string, username string) {

	if strings.Compare(hostname, "") == 0 || strings.Compare(hostname, "localhost") == 0 || strings.Compare(hostname, "127.0.0.1") == 0 {
		hostname = "localhost"
	}

	retval := C.krb5_init_context(&(C.info.go_krb5_context))
	if retval != 0 {
		elog.Fatalf(chopPath(funName()), "Error in krb5_init_context: %d", retval)
		return
	}
	if username != "" {
		elog.Debugln(chopPath(funName()), "Authenticating with user:", username)
		retval = C.krb5_parse_name(C.info.go_krb5_context, C.CString(username), &C.info.go_krb5_client)
		if retval != 0 {
			elog.Fatalf(chopPath(funName()), "Error in krb5_parse_name: %d", retval)
			C.krb5_free_principal(C.info.go_krb5_context, C.info.go_krb5_client)
			C.krb5_free_context(C.info.go_krb5_context)
			return
		}
		retval = C.krb5_cc_cache_match(C.info.go_krb5_context, C.info.go_krb5_client, &(C.info.go_krb5_ccache))
		if retval != 0 {
			elog.Fatalf(chopPath(funName()), "Error in krb5_cc_cache_match: %d", retval)
			C.krb5_free_principal(C.info.go_krb5_context, C.info.go_krb5_client)
			C.krb5_free_context(C.info.go_krb5_context)
			return
		}
	} else {
		retval = C.krb5_cc_default(C.info.go_krb5_context, &(C.info.go_krb5_ccache))
		if retval != 0 {
			elog.Fatalf(chopPath(funName()), "Error in krb5_cc_default: %d", retval)
			C.krb5_free_context(C.info.go_krb5_context)
			return
		}

		retval = C.krb5_cc_get_principal(C.info.go_krb5_context, C.info.go_krb5_ccache, &(C.info.go_krb5_client))
		if retval != 0 {
			elog.Fatalf(chopPath(funName()), "Error in krb5_cc_get_principal: %d", retval)
			C.krb5_cc_close(C.info.go_krb5_context, C.info.go_krb5_ccache)
			C.krb5_free_context(C.info.go_krb5_context)
			return
		}

	}

	retval = C.krb5_unparse_name(C.info.go_krb5_context, C.info.go_krb5_client, &(C.go_krb5_name))
	if retval != 0 {
		elog.Fatalf(chopPath(funName()), "Error in krb5_unparse_name: %d", retval)
		C.krb5_free_principal(C.info.go_krb5_context, C.info.go_krb5_client)
		C.krb5_cc_close(C.info.go_krb5_context, C.info.go_krb5_ccache)
		C.krb5_free_context(C.info.go_krb5_context)
		return
	}

	retval = C.krb5_sname_to_principal(C.info.go_krb5_context, C.CString(hostname), C.CString(GO_KRB_SRVNAM),
		C.KRB5_NT_SRV_HST, &C.server)
	if retval != 0 {
		elog.Fatalf(chopPath(funName()), "Error in krb5_sname_to_principal: %d", retval)
		C.krb5_free_principal(C.info.go_krb5_context, C.info.go_krb5_client)
		C.krb5_cc_close(C.info.go_krb5_context, C.info.go_krb5_ccache)
		C.krb5_free_unparsed_name(C.info.go_krb5_context, C.go_krb5_name)
		C.krb5_free_context(C.info.go_krb5_context)
		return
	}
	socketfd := cn.socketfd
	retval = C.krb5_sendauth(C.info.go_krb5_context, &C.auth_context,
		(C.krb5_pointer)(unsafe.Pointer(&socketfd)), C.CString(GO_KRB_SRVNAM),
		C.info.go_krb5_client, C.server,
		C.AP_OPTS_MUTUAL_REQUIRED,
		nil, nil, /* no creds, use ccache instead */
		C.info.go_krb5_ccache, &C.err_ret, nil, nil)

	if retval != 0 {
		if retval == C.int(C.KRB5_SENDAUTH_REJECTED) {
			elog.Fatalf(chopPath(funName()), "authentication rejected: \"%*s\"", C.err_ret.text.length, C.err_ret.text.data)
			return
		} else {
			elog.Fatalf(chopPath(funName()), "Error in krb5_sendauth: %d", retval)
			return
		}

		C.krb5_free_error(C.info.go_krb5_context, C.err_ret)
	}

	C.krb5_free_principal(C.info.go_krb5_context, C.server)
	C.krb5_free_principal(C.info.go_krb5_context, C.info.go_krb5_client)
	C.krb5_cc_close(C.info.go_krb5_context, C.info.go_krb5_ccache)
	C.krb5_free_unparsed_name(C.info.go_krb5_context, C.go_krb5_name)
	C.krb5_free_context(C.info.go_krb5_context)
}
