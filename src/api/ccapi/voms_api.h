/*********************************************************************
 *
 * Authors: Vincenzo Ciaschini - Vincenzo.Ciaschini@cnaf.infn.it 
 *
 * Copyright (c) 2002, 2003 INFN-CNAF on behalf of the EU DataGrid.
 * For license conditions see LICENSE file or
 * http://www.edg.org/license.html
 *
 * Parts of this code may be based upon or even include verbatim pieces,
 * originally written by other people, in which case the original header
 * follows.
 *
 *********************************************************************/

#ifndef VOMS_API_H
#define VOMS_API_H

#include <fstream>
#include <string>
#include <vector>


extern "C" {
#ifndef NOGLOBUS
#include <gssapi.h>
#else
typedef void * gss_cred_id_t;
typedef void * gss_ctx_id_t;
#endif
#include <openssl/x509.h>
#include <sys/types.h>
#include "newformat.h"
}

/*! \brief User's characteristics: can be repeated.
*/
struct data {
  std::string group; /*!< user's group */
  std::string role;  /*!< user's role */
  std::string cap;   /*!< user's capability */
};

/*!< \brief Generic name-value attribute : can be repeated.
 */
struct attribute {
  std::string name;      /*!< attribute's group */
  std::string qualifier; /*!< attribute's qualifier */
  std::string value;     /*!< attribute's value */
};

struct attributelist {
  std::string grantor;               /*!< Who granted these attributes. */
  std::vector<attribute> attributes; /*!< The attributes themselves.    */
};


/*! \brief The type of data returned.
 */
enum data_type { 
  TYPE_NODATA,  /*!< no data */
  TYPE_STD,     /*!< group, role, capability triplet */
  TYPE_CUSTOM   /*!< result of an S command */
};

struct contactdata {   /*!< You must never allocate directly this structure.
                         Its sizeof() is subject to change without notice.
                         The only supported way to obtain it is via the
                         FindBy* functions. */
  std::string  nick;    /*!< The alias of the server */
  std::string  host;    /*!< The hostname of the server */
  std::string  contact; /*!< The subject of the server's certificate */
  std::string  vo;      /*!< The VO served by this server */
  int          port;	       /*!< The port on which the server is listening */

  int          version; /*!< The version of globus under which the server is running */ 
};

struct voms {
  friend class vomsdata;
  int version;             /*!< 0 means data didn't originate from an AC */
  int siglen;              /*!< The length of the VOMS server signature */
  std::string signature;   /*!< The VOMS server signature */
  std::string user;        /*!< The user's DN, as from his certificate */
  std::string userca;      /*!< The CA which signed the user's certificate */
  std::string server;      /*!< The VOMS server DN, as from its certificate */
  std::string serverca;    /*!< The CA which signed the VOMS certificate */
  std::string voname;      /*!< The name of the VO to which the VOMS belongs */
  std::string uri;         /*!< The URI of the VOMS server */
  std::string date1;       /*!< Beginning of validity of the user info */
  std::string date2;       /*!< End of validity of the user info */
  data_type type;          /*!< The type of data returned */
  std::vector<data> std;   /*!< User's characteristics */
  std::string custom;      /*!< The data returned by an S command */
  /* Data below this line only makes sense if version >= 1 */
  std::vector<std::string> fqan; /*!< Keeps the data in the compact format */
  std::string serial;      /*!< Serial number. "0" if coming from non-ac */
  /* Data below this line is private. */

private:
  void *realdata;                  /*!< Original AC format. */
  X509 *holder;
public:
  voms(const voms &);
  voms();
  voms &operator=(const voms &);
  ~voms();

private:
  struct vomsr *translate();
  friend int TranslateVOMS(struct vomsdatar *vd, std::vector<voms>&v, int *error);

public:
  AC *GetAC();

public:
  std::vector<attributelist>& GetAttributes();   /*!< Generic attributes */
};

enum recurse_type { 
  RECURSE_CHAIN, 
  RECURSE_NONE,
  RECURSE_DEEP
};

enum verify_type {
  VERIFY_FULL      = 0xffffffff,
  VERIFY_NONE      = 0x00000000,
  VERIFY_DATE      = 0x00000001,
  VERIFY_TARGET    = 0x00000002,
  VERIFY_KEY       = 0x00000004,
  VERIFY_SIGN      = 0x00000008,
  VERIFY_ORDER     = 0x00000010,
  VERIFY_ID        = 0x00000020,
  VERIFY_CERTLIST  = 0x00000040
};

/*! \brief Error codes.
*/
enum verror_type { 
  VERR_NONE,
  VERR_NOSOCKET,   /*!< Socket problem*/
  VERR_NOIDENT,    /*!< Cannot identify itself (certificate problem) */
  VERR_COMM,       /*!< Server problem */
  VERR_PARAM,      /*!< Wrong parameters*/
  VERR_NOEXT,      /*!< VOMS extension missing */
  VERR_NOINIT,     /*!< Initialization error */
  VERR_TIME,       /*!< Error in time checking */
  VERR_IDCHECK,    /*!< User data in extension different from the real ones */
  VERR_EXTRAINFO,  /*!< VO name and URI missing */
  VERR_FORMAT,     /*!< Wrong data format */
  VERR_NODATA,     /*!< Empty extension */
  VERR_PARSE,      /*!< Parse error */
  VERR_DIR,        /*!< Directory error */
  VERR_SIGN,       /*!< Signature error */
  VERR_SERVER,     /*!< Unidentifiable VOMS server */
  VERR_MEM,        /*!< Memory problems */
  VERR_VERIFY,     /*!< Generic verification error*/
  //  VERR_IDENT, 
  VERR_TYPE,       /*!< Returned data of unknown type */
  VERR_ORDER,      /*!< Ordering different than required */
  VERR_SERVERCODE, /*!< Error message from the server */
  VERR_NOTAVAIL    /*!< Method not available */
};

typedef bool (*check_sig)(X509 *, void *, verror_type &); /*!<*/

struct vomsdata {
  private:
  class Initializer {
  public:
    Initializer();
  private:
    Initializer(Initializer &);
  };

  private:
  static Initializer init;
  std::string ca_cert_dir;
  std::string voms_cert_dir;
  int duration;
  std::string ordering;
  std::vector<contactdata> servers;
  std::vector<std::string> targets;

  public:
  verror_type error; /*!< Error code */

  vomsdata(std::string voms_dir = "", 
	   std::string cert_dir = ""); /*!< \param voms_dir The directory which contains the certificate 
                                              of the VOMS server
                                       \param cert_dir The directory which contains the certificate of the CA

                                       If voms_dir is empty, the value of the environment variable
                                       X509_VOMS_DIR is taken.

                                       If cert_dir is empty, the value of the environment variable
                                       X509_CERT_DIR is taken.
                                   */

  bool LoadSystemContacts(std::string dir = ""); /*!< Loads the system wide configuration files.
						   \param dir The directory in which the files are stored.

						   If dir is empty, defaults to /opt/edg/etc/vomses.

						   \return True if all went OK, false otherwise.
						 */
  bool LoadUserContacts(std::string dir = ""); /*!< Loads the user-specific configuration files.
						 \param dir The directory in which the files are stored.

						 If dir is empty, defaults to $VOMS_USERCONF. If this is 
						 empty too, defaults to $HOME/.edg/vomses, or to
						 ~/.edg/vomses as a last resort.

						 \return True if all went OK, false otherwise.
						 */

  std::vector<contactdata> FindByAlias(std::string alias); /*!< Finds servers which share a common alias.
							     \param alias The alias to look for.

							     \return The servers found. The order in which
							             they are returned is unspecified.
							   */


  std::vector<contactdata> FindByVO(std::string vo); /*!< Finds servers which serve a common VO
						       \param vo The VO name to look for.

						       \return The servers found. The order in which
						               they are returned is unspecified.
						     */


  void Order(std::string att); /*!< Sets up the ordering of the results.

			    Defines the ordering of the data returned by Contact(). Results are
			    ordered in the same order as the calls to this function.
			    \param att The attribute to be ordered.
			  */

  void ResetOrder(void); /*!< Resets the ordering. */

  void AddTarget(std::string target);         /*!< Adds a target to the AC.

					      \param target The target to be added. it should be a FQDN.
					      */

  std::vector<std::string> ListTargets(void); /*!< Returns the list of targets. */

  void ResetTargets(void);        /*!< Resets the target list. */
  std::string ServerErrors(void); /*!< Gets the error message returned by the server */

  bool Retrieve(X509 *cert, STACK_OF(X509) *chain, 
		recurse_type how = RECURSE_CHAIN); /*!< Extracts the VOMS extension from an X.509 certificate. 
                                                     The function doesn't check the validity of the certificates, 
                                                     but it does check the content of the user data.
                                                     \param cert The certificate with the VOMS extensions
                                                     \param chain The chain of the validation certificates 
                                                           (only the intermediate ones)
                                                     \param how Recursion type
                                                     \return failure (F) or success (T)
                                                   */  
  bool Contact(std::string hostname, int port, 
               std::string servsubject, 
               std::string command); /*!< Contacts a VOMS server to get a certificate

                                    It is the equivalent of the voms_proxy_init command, but 
                                    without the --include functionality.
                                    \param hostname FQDN of the VOMS server
                                    \param port the port on which the VOMS server is listening
                                    \param servsubject the subject of the server's certificate
                                    \param command the command sent to the server
                                    \return failure (F) or success (T)
                                     */

  bool ContactRaw(std::string hostname, int port, 
		  std::string servsubject, 
		  std::string command,
		  std::string &raw,
      int& version);  /*!< Same as Contact, however it does not start the
                           verification process, and the message receviedfrom the server is not parsed.
                         \param hostname FQDN of the VOMS server
                         \param port the port on which the VOMS server is listening
                         \param servsubject the subject of the server's certificate
                         \param command the command sent to the server
                         \param raw OUTPUT PARAMETER the answer from the server
                         \param version OUTPUT PARAMETER the version of the answer
                         \return failure (F) or success (T) */

  void SetVerificationType(verify_type how); /*!< Sets the type of verification done on the data.
                                               \param how The type of verification.
                                             */

  void SetLifetime(int lifetime); /*!< Set requested lifetime for the Contact() call.
                                    \param lifetime Requested lifetime, in seconds
                                  */

  bool Import(std::string buffer);/*!< Converts data from the format used for inclusion 
                                  into a certificate to the internal format

                                     The function does verify the data.
                                     \param buffer contains the data to be converted 
                                     \return Failure (F) or Success (T)
                             */
  bool Export(std::string &data); /*!< Exports data from vomsdata::data to the format 
				    used for inclusion into a certificate. 

				    The function doesn't verify the data
				    \param data The certificate extension
				    \return Failure (F) or Success (T)
				  */
  bool DefaultData(voms &); /*!< Get the default data extension from those present in
			      the pseudo certificate */

  std::vector<voms> data; /*!< User's info, as in the certificate extension.
                          It may contain data gathered from more than one VOMS server, 
                     */
  std::string workvo;     /*!< The value of the -vo option of the voms-proxy-init command */
  std::string extra_data; /*!< The data specified by the user with the --include switch.
 
                          Note that this field doesn't contain the result of a request
                          to the VOMS server, but instead data specified by the user.

                          The reason for the introduction of this extension is to let 
                          a user include important data into his proxy certificate, 
                          like, for example, a kerberos ticket 
                      */
private:
  bool loadfile(std::string, uid_t uid, gid_t gid);
  bool loadfile0(std::string, uid_t uid, gid_t gid);
  bool verifydata(std::string &message, std::string subject, std::string ca, 
                  X509 *holder, voms &v);
  X509 *check(check_sig f, void *data); /*!< Unused.  Only left here for binary compatibility. */
  bool check_cert(X509 *cert);
  bool retrieve(X509 *cert, STACK_OF(X509) *chain, recurse_type how,
                AC_SEQ **listnew, std::string &subject, std::string &ca,
                X509 **holder);
  verify_type ver_type;

  std::string serverrors;
  std::string errmessage;
  
  void seterror(verror_type, std::string);

  bool verifyac(X509 *, X509 *, AC*, voms&);
  bool check_sig_ac(X509 *, void *);
  X509 *check(void *);
  bool my_conn(const std::string&, int, const std::string&, int,
               const std::string&, std::string&, std::string&,
               std::string&);
  bool contact(const std::string&, int, const std::string&,
               const std::string&, std::string&, std::string&,
               std::string&);
  bool verifydata(AC *ac, const std::string& subject, const std::string& ca, 
                  X509 *holder, voms &v);
  bool evaluate(AC_SEQ *, const std::string&, const std::string&, X509*);

public:

  std::string ErrorMessage(void); /*!< Gets a textual description of the error.
            \return A string containg the error message. */
  bool RetrieveFromCtx(gss_ctx_id_t context, recurse_type how); /*!< Gets VOMS information from the given globus context
             \param context The context from which to retrieve the certificate.
             \param how Recursion type
             \return failure (F) or success (T)*/

  bool RetrieveFromCred(gss_cred_id_t credential, recurse_type how);  /*!< Gets VOMS information from the given globus credential
             \param credential The credential from which to retrieve the certificate.
             \param how Recursion type
             \return failure (F) or success (T)*/

  bool Retrieve(X509_EXTENSION *ext); /*!< Gets VOMS information from the given extension
             \param ext The extension to parse.
             \return failure (F) or success (T) */

  bool RetrieveFromProxy(recurse_type how); /*!< Gets VOMS information from an existing globus proxy
             \param how Recursion type
             \return failure (F) or success (T)*/
  ~vomsdata();
private:
  //  X509 *check_file(void *);
  bool check_cert(STACK_OF(X509) *);
  X509 *check_from_certs(AC *ac, const std::string& voname);
  X509 *check_from_file(AC *, std::ifstream&, const std::string &vo, const std::string &filename);

public:
  vomsdata(const vomsdata &);

private:
  int retry_count;
  
public:
  void SetRetryCount(int retryCount);

};


int getMajorVersionNumber(void);
int getMinorVersionNumber(void);
int getPatchVersionNumber(void);

#endif
