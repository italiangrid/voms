#include "config.h"

#include "voms_cert_type.h"
#include "sslutils.h"

#include "openssl/asn1.h"
#include "openssl/x509.h"
#include "openssl/x509v3.h"

#include <ctype.h>
#include <stdio.h>
#include <string.h>

#define LIMITED_PROXY_OID               "1.3.6.1.4.1.3536.1.1.1.9"
#define PROXYCERTINFO_OLD_OID           "1.3.6.1.4.1.3536.1.222"
#define NULL_STR "<null>"


static voms_result_t 
voms_validation_error_with_detail(int code, X509_NAME* subject,
    const char* detail) { 

  char sub_buf[256];

  PRXYerr(PRXYERR_F_VOMS_GET_CERT_TYPE,code);

  X509_NAME_oneline(subject,sub_buf,256);

  if (detail != NULL) {

    ERR_add_error_data(5, 
	": ",
	detail,
	" [subject: '",
	sub_buf,
	"']"); 
  } else {

    ERR_add_error_data(3, 
	"[subject: '",
	sub_buf,
	"']"); 
  }

  return VOMS_ERROR;
}

static voms_result_t 
voms_validation_error(int code, X509_NAME* subject){

  return voms_validation_error_with_detail(code, subject, NULL);

}

static
X509_NAME_ENTRY* 
get_last_cn_entry_from_subject(X509_NAME* subject){

  X509_NAME_ENTRY* ne = NULL;

  if (subject == NULL){
    return NULL;
  }

  if ((ne = X509_NAME_get_entry(subject, X509_NAME_entry_count(subject) -1)) == NULL)
  {
    return NULL;
  }

  if (OBJ_cmp(X509_NAME_ENTRY_get_object(ne), OBJ_nid2obj(NID_commonName))){
    return NULL;
  }

  return ne;
}

static voms_cert_type_t 
get_proxy_type(ASN1_OBJECT *policy_lang){

  int policy_nid = OBJ_obj2nid(policy_lang);
  int limited_proxy_nid = OBJ_txt2nid(LIMITED_PROXY_OID);

  if (policy_nid == NID_id_ppl_inheritAll) 
  {

    return VOMS_CERT_TYPE_IMPERSONATION_PROXY;

  }

  if (policy_nid == NID_Independent)
  {

    return VOMS_CERT_TYPE_INDEPENDENT_PROXY;

  }
  else if (policy_nid == limited_proxy_nid ) 
  {

    return VOMS_CERT_TYPE_LIMITED_PROXY; 

  }
  else 
  {

    return VOMS_CERT_TYPE_RESTRICTED_PROXY;

  }
}

voms_result_t 
voms_get_cert_type(X509* cert, voms_cert_type_t* cert_type){

  voms_result_t result = VOMS_SUCCESS;

  BASIC_CONSTRAINTS* bc_ext = NULL;
  X509_EXTENSION* ext = NULL;
  PROXY_CERT_INFO_EXTENSION *pci_ext = NULL;
  PROXY_POLICY *policy = NULL;
  ASN1_OBJECT *policy_lang = NULL;

  X509_NAME *subject = NULL;	
  X509_NAME *expected_subject = NULL;
  X509_NAME_ENTRY *ne = NULL;
  X509_NAME_ENTRY *new_ne = NULL;

  ASN1_STRING *ne_data = NULL;

  int critical;
  int index = -1;

  *cert_type = VOMS_CERT_TYPE_EEC;
  subject = X509_get_subject_name(cert);

  if ((bc_ext = X509_get_ext_d2i(cert, NID_basic_constraints, &critical, &index)) &&
      bc_ext->ca){

    *cert_type = VOMS_CERT_TYPE_CA;
    goto exit;
  }

  if ((index=X509_get_ext_by_NID(cert, NID_proxyCertInfo,-1)) != -1 &&
      (ext = X509_get_ext(cert,index)) &&
      X509_EXTENSION_get_critical(ext))
  {

    // Found RFC compliant proxy cert info extension, try to deserialize it
    if ((pci_ext = X509V3_EXT_d2i(ext)) == NULL) {

      result = voms_validation_error_with_detail(
	  PRXYERR_R_NON_COMPLIANT_PROXY,
	  subject,
	  "PROXYCERTINFO conversion error");

      goto exit;
    }

    if ((policy = pci_ext->proxyPolicy) == NULL) {

      result = voms_validation_error_with_detail(
	  PRXYERR_R_NON_COMPLIANT_PROXY,
	  subject,
	  "Error accessing policy from PROXYCERTINFO extension");

      goto exit;
    }

    if ((policy_lang = policy->policyLanguage) == NULL) {

      result = voms_validation_error_with_detail(
	  PRXYERR_R_NON_COMPLIANT_PROXY,
	  subject,
	  "Error accessing policy language from PROXYCERTINFO extension");

      goto exit;
    }

    *cert_type = VOMS_CERT_TYPE_RFC | get_proxy_type(policy_lang);

    if (X509_get_ext_by_NID(cert,NID_proxyCertInfo,index) != -1)
    {

      result = voms_validation_error_with_detail(
	  PRXYERR_R_NON_COMPLIANT_PROXY,
	  subject,
	  "Muliple PROXYCERTINFO extensions found");

      goto exit;

    }

  }
  else if ((index=X509_get_ext_by_NID(cert,OBJ_txt2nid(PROXYCERTINFO_OLD_OID),-1)) != -1 &&
      (ext = X509_get_ext(cert,index)) &&
      X509_EXTENSION_get_critical(ext))
  {

    // Found GSI 3 proxy cert info extension, try to deserialize it
    if ((pci_ext = X509V3_EXT_d2i(ext)) == NULL) {


      result = voms_validation_error_with_detail(
	  PRXYERR_R_NON_COMPLIANT_PROXY,
	  subject,
	  "Error converting DER encoded GSI_3 PROXYCERTINFO extension");

      goto exit;
    }

    if ((policy = pci_ext->proxyPolicy) == NULL) {

      result = voms_validation_error_with_detail(
	  PRXYERR_R_NON_COMPLIANT_PROXY,
	  subject,
	  "Error accessing policy from GSI_3 PROXYCERTINFO extension");

      goto exit;
    }

    if ((policy_lang = policy->policyLanguage) == NULL) {

      result = voms_validation_error_with_detail(
	  PRXYERR_R_NON_COMPLIANT_PROXY,
	  subject,
	  "Error accessing policy from GSI_3 PROXYCERTINFO extension");
      goto exit;
    }

    *cert_type = VOMS_CERT_TYPE_GSI_3 | get_proxy_type(policy_lang);

    if (X509_get_ext_by_NID(cert,OBJ_txt2nid(PROXYCERTINFO_OLD_OID),index) != -1)
    {

      result = voms_validation_error_with_detail(
	  PRXYERR_R_NON_COMPLIANT_PROXY,
	  subject,
	  "Muliple GSI_3 PROXYCERTINFO extensions found");

      goto exit;

    }
  }
  else 
  {
    // Check if we have a legacy GSI_2 proxy by looking
    // at the certificate subject
    subject = X509_get_subject_name(cert); 

    if ((ne = get_last_cn_entry_from_subject(subject)) == NULL){

      result = voms_validation_error(
	  PRXYERR_R_ERROR_GETTING_CN_ENTRY,
	  subject);

      goto exit;
    }

    ne_data = X509_NAME_ENTRY_get_data(ne);

    if (ne_data->length == 5 && !memcmp(ne_data->data,"proxy",5))
    {
      *cert_type = VOMS_CERT_TYPE_GSI_2_PROXY;
    }
    else if (ne_data->length == 13 && !memcmp(ne_data->data,"limited proxy",13))
    {
      *cert_type = VOMS_CERT_TYPE_GSI_2_LIMITED_PROXY;
    }
  }

  // Check proxy name if it's a proxy
  if (VOMS_IS_PROXY(*cert_type))
  {

    if ((expected_subject = X509_NAME_dup(X509_get_issuer_name(cert))) == NULL)
    {
      result = voms_validation_error(
	  PRXYERR_R_ERROR_COPYING_SUBJECT,
	  subject);

      goto exit;
    }
    
    subject = X509_get_subject_name(cert);

    if ((ne = get_last_cn_entry_from_subject(subject)) == NULL){

      result = voms_validation_error(
	  PRXYERR_R_ERROR_GETTING_CN_ENTRY,
	  subject);
      goto exit;

    }

    ne_data = X509_NAME_ENTRY_get_data(ne);

    if ((new_ne = X509_NAME_ENTRY_create_by_NID( NULL, NID_commonName,
	    ne_data->type, ne_data->data, -1)) == NULL){

      result = voms_validation_error(
	  PRXYERR_R_ERROR_BUILDING_SUBJECT,
	  subject);

      goto exit;

    }

    if(!X509_NAME_add_entry(expected_subject, new_ne, X509_NAME_entry_count(expected_subject),0))
    {

      result = voms_validation_error(
	  PRXYERR_R_ERROR_BUILDING_SUBJECT,
	  subject);
      goto exit;
    }

    if (X509_NAME_cmp(expected_subject,subject))
    {

      result = voms_validation_error_with_detail(
	  PRXYERR_R_NON_COMPLIANT_PROXY,
	  subject,
	  "Issuer name + proxy CN entry does not equal subject name");

      goto exit;
    }
  }

  result = VOMS_SUCCESS;

exit:

  if (bc_ext) 
  {
    BASIC_CONSTRAINTS_free(bc_ext);
  }

  if (pci_ext)
  {
    PROXY_CERT_INFO_EXTENSION_free(pci_ext);
  }

  if (expected_subject)
  {
    X509_NAME_free(expected_subject);

  }

  if (new_ne)
  {
    X509_NAME_ENTRY_free(new_ne);
  }

  return result;
}
