/*
 * Copyright 2020 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include "internal/cryptlib.h"
#include <openssl/asn1.h>
#include <openssl/conf.h>
#include <openssl/x509v3.h>
#include "ext_dat.h"

const X509V3_EXT_METHOD v3_ns_ia5_list[] = {
    EXT_IA5STRING(NID_netscape_base_url),
    EXT_IA5STRING(NID_netscape_revocation_url),
    EXT_IA5STRING(NID_netscape_ca_revocation_url),
    EXT_IA5STRING(NID_netscape_renewal_url),
    EXT_IA5STRING(NID_netscape_ca_policy_url),
    EXT_IA5STRING(NID_netscape_ssl_server_name),
    EXT_IA5STRING(NID_netscape_comment)
};

#define EXT_UTF8STRING(nid) EXT_ASN1_STRING(nid, ASN1_UTF8STRING)

const X509V3_EXT_METHOD v3_utf8_list[] = {
    EXT_UTF8STRING(NID_subjectSignTool),
    EXT_UTF8STRING(NID_issuerSignTool)
};

char *i2s_ASN1_STRING(X509V3_EXT_METHOD *method, ASN1_STRING *asn1string)
{
    char *tmp;

    if (asn1string == NULL || asn1string->length < 0)
        return NULL;
    if ((tmp = OPENSSL_malloc(asn1string->length + 1)) == NULL) {
        X509V3err(X509V3_F_I2S_ASN1_STRING, ERR_R_MALLOC_FAILURE);
        return NULL;
    }
    memcpy(tmp, asn1string->data, asn1string->length);
    tmp[asn1string->length] = 0;
    return tmp;
}

ASN1_STRING *s2i_ASN1_STRING(X509V3_EXT_METHOD *method,
                             X509V3_CTX *ctx, const char *str)
{
    ASN1_STRING *asn1string;

    if (str == NULL) {
        X509V3err(X509V3_F_S2I_ASN1_STRING,
                  X509V3_R_INVALID_NULL_ARGUMENT);
        return NULL;
    }
    if ((asn1string = ASN1_STRING_new()) == NULL) {
        X509V3err(X509V3_F_S2I_ASN1_STRING, ERR_R_MALLOC_FAILURE);
        return NULL;
    }
    if (!ASN1_STRING_set(asn1string, str, strlen(str))) {
        ASN1_STRING_free(asn1string);
        return NULL;
    }
#ifdef CHARSET_EBCDIC
    ebcdic2ascii(asn1string->data, asn1string->data, asn1string->length);
#endif                          /* CHARSET_EBCDIC */
    return asn1string;
}
