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
/*********************************************************************
 * Parts of this code shamelessly stolen from Joni's code.
 *********************************************************************/
package org.glite.voms;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.util.Vector;
import java.util.regex.Pattern;
import java.security.cert.X509Certificate;
import org.apache.log4j.Logger;

public class Namespace
{
  private static Logger logger = Logger.getLogger(Namespace.class.getName());
//   private static final Pattern namespace_self_permit_pattern = Pattern.compile("to\\s+issuer\\s+self\\s+permit\\s+\"(.*)\"", Pattern.CASE_INSENSITIVE);
//   private static final Pattern namespace_self_deny_pattern = Pattern.compile("to\\s+issuer\\s+self\\s+deny\\s+\"(.*)\"", Pattern.CASE_INSENSITIVE);
//   private static final Pattern namespace_issuer_permit_pattern = Pattern.compile("to\\s+issuer\\s+\"(.*)\"\\s+permit\\s+subject\\s+\"(.*)\"", Pattern.CASE_INSENSITIVE);
//   private static final Pattern namespace_issuer_deny_pattern = Pattern.compile("to\\s+issuer\\s+\"(.*)\"\\s+deny\\s+subject\\s+\"(.*)\"", Pattern.CASE_INSENSITIVE);
  private static final Pattern splitPattern = Pattern.compile("to issuer|permit|deny|subject", Pattern.CASE_INSENSITIVE);
  private Vector issuer  = new Vector();
  private Vector subject = new Vector();
  private Vector permit  = new Vector();
  private int current = -1;
  private String gname = "";

  public Namespace(File f) throws IOException {
    parse(f);
  }

  public String getName() {
    return gname;
  }

  void parse(File f) throws IOException {
    BufferedReader theBuffer = new BufferedReader(new FileReader(f));
    String s = null;

    gname = PKIUtils.getBaseName(f);

    StringBuilder theLine = new StringBuilder();

    // Concatenate lines ending with '\'

    do {
      do {
          s = theBuffer.readLine();

          if (s != null) {
              // ignore comments
              if (s.trim().startsWith("~"))
                  continue;
 
              theLine.append(s);
          }
      } while (s != null && s.endsWith("\\"));

      String finalLine = theLine.toString().trim();

      // Idea for the splitting shamelessly taken from Joni.
      // Thanks, Joni!
      String[] strings = splitPattern.split(finalLine, 0);

      if (strings.length == 4) {
          String permitCode = "";

          if (finalLine.toLowerCase().contains(" deny ")) {
              permitCode = "DENY";
          } else if (finalLine.toLowerCase().contains(" permit ")) {
              permitCode = "PERMIT";
          }

          if (!permitCode.equals("")) {
              String tempIssuer = strings[1];
              // First one should be the subject
              if (tempIssuer.toLowerCase().equals("self"))
                  issuer.add("SELF");
              else
                  issuer.add(tempIssuer.substring(1, strings[1].length()));

              // third one should be subject
              subject.add(strings[3].substring(1, strings[3].length()));
              permit.add(permitCode);
          }
      }
    } while (s != null);
  }

  public int findIssuer(X509Certificate issuer) {
    return findIssuer(issuer, -1);
  }

  public int findIssuer(X509Certificate issuerCert, int previous) {
    if (previous < -1)
      return -1;

    String currentSubj = PKIUtils.getOpenSSLFormatPrincipal(issuerCert.getSubjectDN());
    String currentSubjReversed = PKIUtils.getOpenSSLFormatPrincipal(issuerCert.getSubjectDN(), true);

    int index = issuer.indexOf(currentSubj, previous +1);

    if (index == -1)
      index = issuer.indexOf(currentSubjReversed, previous +1);

    if (index == -1) {
      String hash = PKIUtils.getHash(issuerCert);
      if ((hash+".namespace").equals(gname))
          return issuer.indexOf("SELF", previous+1);
    }
    return index;
  }

  /**
   * Sets the indicate record as the current record.
   *
   * @param index the record number
   *
   * @throws IllegalArgumentException if the record number is too great
   * or < 0.
   */
  public void setCurrent(int index) {
    if (index > issuer.size() || index < 0)
      throw new IllegalArgumentException("Index out of bounds for Namespace " + gname);
    current = index;
  }

  public String getIssuer() {
    if (current != -1)
      return (String)issuer.elementAt(current);
    else
      throw new IllegalArgumentException("Current record must be set in Namespace object " + gname);
  }

  public String getSubject() {
    if (current != -1)
      return (String)subject.elementAt(current);
    else
      throw new IllegalArgumentException("Current record must be set in Namespace object " + gname);
  }

  public boolean getPermit() {
    if (current != -1)
      return subject.elementAt(current).equals("PERMIT");
    else
      throw new IllegalArgumentException("Current record must be set in Namespace object " + gname);
  }
}
 