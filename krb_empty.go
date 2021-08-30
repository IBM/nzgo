// +build !kerberos

// This file is to provide defination of go_krb5_sendauth() so that it doesn't fail on compilation.
// Ideally this func should never be called when authentication is other than 'kerberos'
// If authentication is kerberos then below tag should be used during compilation
// 	go build -tags kerberos
// If above tag is not used then the below func would get executed
// If above tag is used then the func defined in krb.go would be called.

package nzgo

func (cn *conn) go_krb5_sendauth(hostname string, username string) {
	elog.Fatalf(chopPath(funName()), "Building go without kerberos tags")
}


