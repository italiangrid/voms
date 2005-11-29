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
#include "config.h"

void declareOIDs(void)
{
#define idpkix                "1.3.6.1.5.5.7"
#define idpkcs9               "1.2.840.113549.1.9"
#define idpe                  idpkix ".1"
#define idce                  "2.5.29"
#define idaca                 idpkix ".10"
#define idat                  "2.5.4"
#define idpeacauditIdentity   idpe ".4"
#define idcetargetInformation idce ".55"
#define idceauthKeyIdentifier idce ".35"
#define idceauthInfoAccess    idpe ".1"
#define idcecRLDistPoints     idce ".31"
#define idcenoRevAvail        idce ".56"
#define idceTargets           idce ".55"
#define idacaauthentInfo      idaca ".1"
#define idacaaccessIdentity   idaca ".2"
#define idacachargIdentity    idaca ".3"
#define idacagroup            idaca ".4"
#define idatclearance         "2.5.1.5.5"
#define voms                  "1.3.6.1.4.1.8005.100.100.1"
#define incfile               "1.3.6.1.4.1.8005.100.100.2"
#define vo                    "1.3.6.1.4.1.8005.100.100.3"
#define idatcap               "1.3.6.1.4.1.8005.100.100.4"
#define acseq                 "1.3.6.1.4.1.8005.100.100.5"
#define order                 "1.3.6.1.4.1.8005.100.100.6"
#define email                 idpkcs9 ".1"

#define PROXYCERTINFO         "1.3.6.1.4.1.3536.1.222"

#define OBJC(c,n) OBJ_create(c,n,#c)

  static int done=0;
  if (done)
    return;

  done=1;
  OBJ_create(email, "Email", "Email");
  OBJC(idatcap,"idatcap");
  OBJC(idcenoRevAvail, "noRevAvail");
  OBJC(idceauthKeyIdentifier, "authKeyId");
  OBJC(idceTargets, "idceTargets");
  OBJC(acseq, "acseq");
  OBJC(order, "order");
  OBJC(voms, "voms");
  OBJC(incfile, "incfile");
  OBJC(vo, "vo");

  /* Proxy Certificate Extension's related objects */
  OBJC(PROXYCERTINFO, "PROXYCERTINFO");

}

void InitAC(void)
{
  static int i = 0;
  if (i) return;
  i=1;
  (void)declareOIDs();
  (void)initEx();
}
