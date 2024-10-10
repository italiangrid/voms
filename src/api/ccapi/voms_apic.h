/*********************************************************************
 *
 * Authors: Vincenzo Ciaschini - Vincenzo.Ciaschini@cnaf.infn.it 
 *
 * Copyright (c) Members of the EGEE Collaboration. 2004-2010.
 * See http://www.eu-egee.org/partners/ for details on the copyright holders.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * Parts of this code may be based upon or even include verbatim pieces,
 * originally written by other people, in which case the original header
 * follows.
 *
 *********************************************************************/

#ifndef VOMS_APIC_H
#define VOMS_APIC_H

#ifdef __cplusplus
extern "C" {
#endif

#define NOGLOBUS
#if !(defined(GSSAPI_H_) || defined(_GSSAPI_H) || defined(_GSSAPI_H_))
typedef void * gss_cred_id_t;
typedef void * gss_ctx_id_t;
#endif

#include <openssl/x509.h>
#include <time.h>

#include "newformat.h"

/*#include "voms_api.h"*/

/*!< \brief User's characteristics: can be repeated. 
*/
struct data {
  char *group; /*!< user's group */
  char *role;  /*!< user's role */
  char *cap;   /*!< user's capability */
};

struct attribute {
  const char *name;
  const char *value;
  const char *qualifier;
};

struct contactdata { /*!< You must never allocate directly this structure. Its sizeof() is
                        subject to change without notice. The only supported way to obtain it
                        is via the VOMS_FindBy* functions. */
  char *nick;     /*!< The alias of the server */
  char *host;     /*!< The hostname of the server */
  char *contact;  /*!< The subject of the server's certificate */
  char *vo;       /*!< The VO served by this server */
  int   port;     /*!< The port on which the server is listening */                            
  char *reserved; /*!< HANDS OFF! */
  int   version;  /*!< The version of Globus on which this server runs. */
};

/*!< \brief The type of data returned.
 */

#define  TYPE_NODATA 0  /*!< no data */
#define  TYPE_STD    1  /*!< group, role, capability triplet */
#define  TYPE_CUSTOM 2  /*!< result of an S command */


struct voms {
  int siglen;        /*!< The length of the VOMS server signature */
  char *signature;   /*!< The VOMS server signature */
  char *user;        /*!< The user's DN, as from his certificate */
  char *userca;      /*!< The CA which signed the user's certificate */
  char *server;      /*!< The VOMS server DN, as from its certificate */
  char *serverca;    /*!< The CA which signed the VOMS certificate */
  char *voname;      /*!< The name of the VO to which the VOMS belongs */
  char *uri;         /*!< The URI of the VOMS server */
  char *date1;       /*!< Beginning of validity of the user info */
  char *date2;       /*!< End of validity of the user info */
  int   type;        /*!< The type of data returned */
  struct data **std; /*!< User's characteristics */
  char *custom;      /*!< The data returned by an S command */
  int datalen;
  int version;
  char **fqan;    /*!< User's attributes in compact format */
  char *serial;      /*!< Serial number. Only significant if coming from AC. 
		       Null otherwise */
  /* Fields below this line are reserved. */
  AC *ac;
  X509 *holder;
};


#define RECURSE_CHAIN 0
#define RECURSE_NONE  1

#define VERIFY_FULL      0xffffffff
#define VERIFY_NONE      0x00000000
#define VERIFY_DATE      0x00000001
#define VERIFY_NOTARGET  0x00000002
#define VERIFY_KEY       0x00000004
#define VERIFY_SIGN      0x00000008
#define VERIFY_ORDER     0x00000010
#define VERIFY_ID        0x00000020
#define VERIFY_CERTLIST  0x00000040
/*! \brief Error codes.
*/

#define VERR_NONE       0
#define VERR_NOSOCKET   1  /*!< Socket problem*/
#define VERR_NOIDENT    2  /*!< Cannot identify itself (certificate problem) */
#define VERR_COMM       3  /*!< Server problem */
#define VERR_PARAM      4  /*!< Wrong parameters*/
#define VERR_NOEXT      5  /*!< VOMS extension missing */
#define VERR_NOINIT     6  /*!< Initialization error */
#define VERR_TIME       7  /*!< Error in time checking */
#define VERR_IDCHECK    8  /*!< User data in extension different from the real
                             ones */
#define VERR_EXTRAINFO  9  /*!< VO name and URI missing */
#define VERR_FORMAT     10 /*!< Wrong data format */
#define VERR_NODATA     11 /*!< Empty extension */
#define VERR_PARSE      12 /*!< Parse error */
#define VERR_DIR        13 /*!< Directory error */
#define VERR_SIGN       14 /*!< Signature error */
#define VERR_SERVER     15 /*!< Unidentifiable VOMS server */
#define VERR_MEM        16 /*!< Memory problems */
#define VERR_VERIFY     17 /*!< Generic verification error*/
#define VERR_TYPE       18 /*!< Returned data of unknown type */
#define VERR_ORDER      19 /*!< Ordering different than required */
#define VERR_SERVERCODE 20 /*!< Error from the server */
#define VERR_NOTAVAIL   21 /*!< Method not available */

struct vomsdata {
  char *cdir;
  char *vdir;
  struct voms **data; /*!< User's info, as in the certificate extension.
                           It may contain data gathered from more than one
                           VOMS server, */
  char *workvo;     /*!< The value of the -vo option of the voms-proxy-init
                         command */
  char *extra_data; /*!< The data specified by the user with the --include
                         switch. 
                         Note that this field doesn't contain the result of a
                         request to the VOMS server, but instead data specified
                         by the user. 
                         The reason for the introduction of this extension is
                         to let a user include important data into his proxy
                         certificate, like, for example, a kerberos ticket 
                    */
  int volen;
  int extralen;
  /* Fields below this line are reserved. */
  struct vomsdata *real;
};

extern struct contactdata **VOMS_FindByAlias(struct vomsdata *vd, char *alias, 
					     char *system, char *user, 
					     int *error); /*!< Gets a list of VOMS servers which share an alias.
							    \param vd The correctly initialized vomsdata structured.
							    \param alias The alias to look for.
							    \param system The directory in which to look for the system
							                  configuration files. If NULL, defaults to
									  /opt/edc/etc/vomses
							    \param user The directory in which to look for the user configuration
							                files. Defaults to $VOMS_USERCONF if NULL. Again defaults
									to $HOME/.edg/vomses if the latter is NULL, or to
									~/.edg/vomses as a last resort.
							    \param error RETURN PARAMETER: qualifies the error message.

							    \return NULL, or a NULL-terminated vector of contactdata structures.
							            The only supported way to free this array is via the
								    VOMS_DeleteContacts function. Note also that the order in
							            which the servers are returned is unspecified.*/


extern struct contactdata **VOMS_FindByVO(struct vomsdata *vd, char *vo, 
					  char *system, char *user, 
					  int *error);  /*!< Gets a list of VOMS servers which serve the same VO.
							    \param vd The correctly initialized vomsdata structured.
							    \param vo The VO to look for.
							    \param system The directory in which to look for the system
							                  configuration files. If NULL, defaults to
									  /opt/edc/etc/vomses
							    \param user The directory in which to look for the user configuration
							                files. Defaults to $VOMS_USERCONF if NULL. Again defaults
									to $HOME/.edg/vomses if the latter is NULL, or to
									~/.edg/vomses as a last resort.
							    \param error RETURN PARAMETER: qualifies the error message.

							    \return NULL, or a NULL-terminated vector of contactdata structures.
							            The only supported way to free this array is via the
								    VOMS_DeleteContacts function. Note also that the order in
							            which the servers are returned is unspecified.*/


extern void VOMS_DeleteContacts(struct contactdata **list); /*!< Frees a contactdata vector.
							      \param list The vector to free.*/

extern struct vomsdata *VOMS_Init(char *voms, char *cert); /*!< Initializes a vomsdata structure for use by the other functions.
						       N.B: This is the ONLY way to correctly initialize a vomsdata structure. It
						            is also forbidden to directly take the sizeof() of this structure.
						       \param voms The directory which contains the certificates of the VOMS servers
						       \param cert The directory which contains the CA certificates

						       If voms_dir is empty, the value of the environment variable
						       X509_VOMS_DIR is taken

						       If cert_dir is empty, the value of the environment variable
						       X509_CERT_DIR is taken

						       \return NULL for failure, or a pointer to a properly initialized structure. */

extern struct voms *VOMS_Copy(struct voms *v, int *error); /*!< Copies a voms structure.
							     N.B: This is the ONLY way to correctly initialize a voms structure as a
                        copy of another voms structure.
							     \param v The structure to copy.
							     \param error RETURN PARAMETER: qualifies the error message.

							     \return NULL (error) or the new voms structure. */

extern struct vomsdata *VOMS_CopyAll(struct vomsdata *vd, int *error); /*!< Copies a vomsdata structure.
									 N.B: This is the ONLY way to correctly initialize a vomsdata structure as a
                        copy of another vomsdata structure.
									 \param vd The structure to copy.
									 \param error RETURN PARAMETER: qualifies the error message.

									 \return NULL (error) or the new vomsdata structure. */

extern void VOMS_Delete(struct voms *v); /*!< Deletes a voms structure
					   \param v Pointer to the structure to delete.*/

extern int VOMS_AddTarget(struct vomsdata *vd, char *target, int *error); /*!< Adds a target to the AC.
									    \param vd The vomsdata structure.
									    \param target The target to add. It should be a FQDN.
									    \param error RETURN PARAMETER: qualifies the error message.
									    \return failure (0) or success (<>0) */
extern void VOMS_FreeTargets(struct vomsdata *vd, int *error);            /*!< Delete the targets from the AC.
									    \param vd The vomsdata structure.
									    \param error RETURN PARAMETER: qualifies the error message. */

extern char *VOMS_ListTargets(struct vomsdata *vd, int *error);          /*< Gets the list of targets for the AC.
									    \param vd The vomsdata structure.
									    \param error RETURN PARAMETER: qualifies the error message. */

extern int VOMS_SetVerificationType(int type, struct vomsdata *vd, int *error); /* Sets the verification type.
										   \param type. The verification type.
										   \param vd The vomsdata structure.
										   \param error RETURN PARAMETER: qualifies the error message. */

extern int VOMS_SetLifetime(int length, struct vomsdata *vd,
			    int *error); /*!< Set requested lifetime for VOMS_Contact() calls.
					   \param length Lifetime requested.
					   \param vd RETURN PARAMETER: contains the modified data.
					   \param error RETURN PARAMETER: Qualifies the error message
					   \return failure (0) or success (<>0)
					 */

extern void VOMS_Destroy(struct vomsdata *vd); /*!< Destroys a proper vomsdata structure
						 /param vd The structure to deallocate. */

extern int VOMS_ResetOrder(struct vomsdata *vd, int *error); /*!< Unsets the return order of the attributes.
							       \param vd RETURN PARAMETER: contains the modified data.
							       \param error RETURN PARAMETER: Qualifies the error message
							       \return failure (0) or success (<>0)
							     */

extern int VOMS_Ordering(char *order, struct vomsdata *vd, int *error); /*!< Further specified the order of the returned attributes.
									  Please do note that calls are cumulative unless VOMS_ResetOrder()
									  is called.

									  \param order the group:role attribute.
									  \param vd RETURN PARAMETER: contains the modified data.
									  \param error RETURN PARAMETER: Qualifies the error message
									  \return failure (0) or success (<>0)
									*/

extern int VOMS_Contact(char *hostname, int port, char *servsubject,
			char *command, struct vomsdata *vd, int *error);  /*!< Contacts a VOMS server to get a certificate

				    It is the equivalent of the voms_proxy_init command, but 
                                    without the --include functionality.
                                    \param hostname FQDN of the VOMS server
                                    \param port the port on which the VOMS server is listening
                                    \param servsubject the subject of the server's certificate
                                    \param command Command
				    \param vd RETURN PARAMETER: contains the data returned by the connection
				    \param error RETURN PARAMETER: Qualifies the error message
                                    \return failure (0) or success (<>0)
				*/

extern int VOMS_ContactRaw(char *hostname, int port, char *servsubject,
			   char *command, void **data, int *datalen, int *version,
			   struct vomsdata *vd, int *error); /*!< 
         The same as VOMS_Contact, except that instead of starting the verification
				 process, the data is returned as is in the \param data and \param datalen
				 fields.
         \param hostname FQDN of the VOMS server
         \param port the port on which the VOMS server is listening
         \param servsubject the subject of the server's certificate
         \param command the command sent to the server
         \param version is the version number of the data.
         \param vd RETURN PARAMETER: contains the data returned by the connection
         \param error RETURN PARAMETER: Qualifies the error message
         \return failure (0) or success (<>0)

							     */

extern int VOMS_Retrieve(X509 *cert, STACK_OF(X509) *chain, int how,
			 struct vomsdata *vd, int *error);  /*!< Extracts the VOMS extension from an X.509 certificate. 

                                                     The function doesn't check the validity of the certificates, 
                                                     but it does check the content of the user data.
                                                     \param cert The certificate with the VOMS extensions
                                                     \param chain The chain of the validation certificates 
                                                           (only the intermediate ones)
                                                     \param how Recursion type
						     \param vd RETURN PARAMETER: contains the data returned by the connection
						     \param error RETURN PARAMETER: Qualifies the error message
						     \return failure (0) or success (<>0)
                                                   */  
extern int VOMS_Import(char *buffer, int buflen, struct vomsdata *vd, int *error); /*!<
              Converts data from the format used for inclusion 
              into a certificate to the internal format

              The function does verify the data.
             \param buffer contains the data to be converted 
				     \param buflen contains the length of buffer
				     \param vd RETURN PARAMETER: contains the data returned by the connection
				     \param error RETURN PARAMETER: Qualifies the error message
				     \return failure (0) or success (<>0)
                             */
extern int VOMS_Export(char **buffer, int *buflen, struct vomsdata *vd, int *error); /*!< Converts data into a test format
             \param buffer OUTPUT PARAMETER contains the converted data
				     \param buflen OUTPUT PARAMETER contains the length of buffer
				     \param vd contains the data to convert
				     \param error RETURN PARAMETER Qualifies the error message
				     \return failure (0) or success (<>0)*/

extern struct voms *VOMS_DefaultData(struct vomsdata *vd, int *error); /*!< Gets the default attributes from a vomsdata
									 structure.
									 \param vd the vomsdata structure to analyze
									 \param error RETURN PARAMETER: Qualifies the error message
									 \return a pointer to the relevant voms structure. DO NOT
									 modify the fields.
								       */

extern char *VOMS_ErrorMessage(struct vomsdata *vd, int error, char *buffer, int len); /*!< Gets a textual description of the error.
            \param vd The vomsdata structure to analyze
            \param error The error returned by the last function
            \param buffer A pointer to a buffer where the error message will 
                          be written.  If NULL, then memory is allocated by the 
                          function, and will have to be free()ed by the caller.
            \param len    The length of the memory pointed to by the buffer parameter.
            \return A pointer to the error message. */


extern int VOMS_RetrieveEXT(X509_EXTENSION *ext, struct vomsdata *vd, int *error); /*!< Gets VOMS information from the given extension
             \param ext The extension to parse.
				     \param vd RETURN PARAMETER: contains the data returned by the connection
				     \param error RETURN PARAMETER: Qualifies the error message
             \return failure (0) or success (<>0) */

extern int VOMS_RetrieveFromCred(gss_cred_id_t cred, int how, struct vomsdata *vd, int *error); /*!< Gets VOMS information from the given globus credential
             \param cred The credential from which to retrieve the certificate.
             \param how Recursion type
             \param vd RETURN PARAMETER: contains the data returned by the connection
             \param error RETURN PARAMETER: Qualifies the error message
             \return failure (0) or success (<>0)*/

extern int VOMS_RetrieveFromFile(FILE *file, int how, struct vomsdata *vd, int *error); /*!< Gets VOMS information from the given globus credential
             \param file The file from which to retrieve the certificate.
             \param how Recursion type
             \param vd RETURN PARAMETER: contains the data returned by the connection
             \param error RETURN PARAMETER: Qualifies the error message
             \return failure (0) or success (<>0)*/

extern int VOMS_RetrieveFromCtx(gss_ctx_id_t ctx, int how, struct vomsdata *vd, int *error); /*!< Gets VOMS information from the given globus context
             \param ctx The context from which to retrieve the certificate.
             \param how Recursion type
             \param vd RETURN PARAMETER: contains the data returned by the connection
             \param error RETURN PARAMETER: Qualifies the error message
             \return failure (0) or success (<>0)*/

extern int VOMS_RetrieveFromProxy(int how, struct vomsdata *vd, int *error); /*!< Gets VOMS information from an existing globus proxy
             \param how Recursion type
             \param vd RETURN PARAMETER: contains the data returned by the connection
             \param error RETURN PARAMETER: Qualifies the error message
             \return failure (0) or success (<>0)*/

extern int VOMS_RetrieveFromAC(AC*ac, struct vomsdata *vd, int *error);  /*!< Gets VOMS information from an existing globus proxy
             \param ac AC from which to get the credentials
             \param vd RETURN PARAMETER: contains the data returned by the connection
             \param error RETURN PARAMETER: Qualifies the error message
             \return failure (0) or success (<>0)*/

extern int VOMS_GetAttributeSourcesNumber(struct voms *v, struct vomsdata *vd, int *error);
extern int VOMS_GetAttributeSourceHandle(struct voms *v, int num, struct vomsdata *vd, int *error);
extern const char *VOMS_GetAttributeGrantor(struct voms *v, int handle, struct vomsdata *vd, int *error);
extern int VOMS_GetAttributesNumber(struct voms *v, int handle, struct vomsdata *vd, int *error);
extern int VOMS_GetAttribute(struct voms *v, int handle, int num, struct attribute *at, struct vomsdata *vd, int *error);

extern struct vomsdata *VOMS_Duplicate(struct vomsdata *vd);
extern AC *VOMS_GetAC(struct voms *v);

extern int getMajorVersionNumber(void);
extern int getMinorVersionNumber(void);
extern int getPatchVersionNumber(void);

extern int VOMS_SetVerificationTime(time_t verificationtime, struct vomsdata *vd, int *error);
extern char **VOMS_GetTargetsList(struct voms *v, struct vomsdata *vd, int *error);
extern void VOMS_FreeTargetsList(char **);

extern int VOMS_SetTimeout(int t, struct vomsdata *vd, int *error);
extern int VOMS_LoadCredentials(X509 *cert, EVP_PKEY *pkey, STACK_OF(X509)* chain, struct vomsdata *vd, int *error);

#ifdef __cplusplus
}
#endif

#endif


