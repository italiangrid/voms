/*********************************************************************
 *
 * Authors: 
 *      Andrea Ceccanti    - andrea.ceccanti@cnaf.infn.it 
 *      Vincenzo Ciaschini - vincenzo.ciaschini@cnaf.infn.it
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
package org.glite.voms.contact;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.ByteArrayInputStream;
import java.io.InputStream;

import java.text.ParseException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.Iterator;
import java.util.List;
import java.util.Set;

import java.security.Security;
import java.security.SecureRandom;
import java.security.Principal;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.cert.Certificate;


import org.apache.log4j.Logger;
import org.glite.voms.PKIVerifier;
import org.glite.voms.PKIUtils;
import org.glite.voms.ac.AttributeCertificate;

import java.net.HttpURLConnection;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLPeerUnverifiedException;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;

import java.net.URL;

import org.bouncycastle.jce.provider.BouncyCastleProvider;


/**
 *
 * This class implements the voms-proxy-init functionality.
 * 
 * @author Andrea Ceccanti
 *
 */
public class VOMSProxyInit {

    private static final Logger log = Logger.getLogger( VOMSProxyInit.class );
    
    private static VOMSProxyInit instance;
    
    private VOMSServerMap serverMap;
    private UserCredentials userCredentials;
    private VOMSProtocol protocol = VOMSProtocol.instance();
    
    private String proxyOutputFile = File.separator+"tmp"+File.separator+"x509up_u_"+System.getProperty( "user.name" ); 
    
    private int proxyLifetime = VOMSProxyBuilder.DEFAULT_PROXY_LIFETIME;
    
    private int proxyType = VOMSProxyBuilder.DEFAULT_PROXY_TYPE;
    
    private int delegationType = VOMSProxyBuilder.DEFAULT_DELEGATION_TYPE;

    private String policyType = null;

    private int bits = 1024;

    private VOMSWarningMessage[] warnings = null;

    static {
        if (Security.getProvider("BC") == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    public VOMSProxyInit(String privateKeyPassword){
    
        try {
            
            serverMap = VOMSESFileParser.instance().buildServerMap();
            
            userCredentials = UserCredentials.instance(privateKeyPassword);
            
        } catch ( IOException e ) {
        
            log.error( "Error parsing vomses files: "+e.getMessage() );
            if (log.isDebugEnabled())
                log.error(e.getMessage(),e);
            
            throw new VOMSException(e);
        }
        
        
    }

    private VOMSProxyInit(UserCredentials credentials) {
        if (credentials == null)
            throw new VOMSException("Unable to find GlobusCredentials!");

        userCredentials = credentials;

        try {
            serverMap = VOMSESFileParser.instance().buildServerMap();
        } catch ( IOException e ) {        
            log.error( "Error parsing vomses files: "+e.getMessage() );
            if (log.isDebugEnabled())
                log.error(e.getMessage(),e);
            
            throw new VOMSException(e);
        }        
    }

    public static VOMSProxyInit instance(String privateKeyPassword){
        return new VOMSProxyInit(privateKeyPassword);
    }
    
    public static VOMSProxyInit instance(){
        return new VOMSProxyInit((String)null);
    }

    public static VOMSProxyInit instance(UserCredentials credentials) {
        return new VOMSProxyInit(credentials);
    }

    public void addVomsServer(VOMSServerInfo info){
        
        serverMap.add( info );
        
    }
    
    public synchronized AttributeCertificate getVomsAC(VOMSRequestOptions requestOptions){
        warnings = null;
        if (requestOptions.getVoName() == null)
            throw new VOMSException("Please specify a vo name to create a voms ac.");
        
        Set servers = serverMap.get( requestOptions.getVoName());

        if (servers ==  null)
            throw new VOMSException("Unknown VO '"+requestOptions.getVoName()+"'. Check the VO name or your vomses configuration files.");
        
        Iterator serverIter = servers.iterator();
        
        while(serverIter.hasNext()){
            
            VOMSServerInfo serverInfo = (VOMSServerInfo) serverIter.next();
            
            try{
            
                VOMSResponse response = contactServer( serverInfo, requestOptions );
                if (!response.hasErrors()){
                    log.debug("No errors");
                    if (response.hasWarnings())
                        logAndSetWarningMessages(response);

                    AttributeCertificate ac = VOMSProxyBuilder.buildAC(response.getAC());
                    log.info( "Got AC from VOMS server "+serverInfo.compactString() );
                    
                    if (log.isDebugEnabled()){
                        
                        try {
                            log.debug( "AC validity period:\nNotBefore:"+ac.getNotBefore()+"\nNotAfter:"+ac.getNotAfter() );
                     
                        } catch ( ParseException e ) {
                            
                            log.error( e.getMessage(),e );
                            e.printStackTrace();
                        }
                        
                    }
                    
                    return ac;
                }
                
                log.error( "Got error response from VOMS server "+serverInfo.compactString() );
                logErrorMessages( response );
                
            }catch(VOMSException e){
                
                log.error(e.getMessage());
                if (log.isDebugEnabled()){
                    log.error(e.getMessage(),e);
                }
                
                if (serverIter.hasNext())
                    continue;
                
                throw(e);
            }
        }
        
        return null;            
    }

    public synchronized String getVomsData(VOMSRequestOptions requestOptions){
        warnings = null;

        if (requestOptions.getVoName() == null)
            throw new VOMSException("Please specify a vo name to create a voms ac.");
        
        Set servers = serverMap.get( requestOptions.getVoName());

        if (servers ==  null)
            throw new VOMSException("Unknown VO '"+requestOptions.getVoName()+"'. Check the VO name or your vomses configuration files.");
        
        Iterator serverIter = servers.iterator();
        
        while(serverIter.hasNext()){
            
            VOMSServerInfo serverInfo = (VOMSServerInfo) serverIter.next();
            
            try{
            
                VOMSResponse response = contactServer( serverInfo, requestOptions );
                
                if (!response.hasErrors()){

                    if (response.hasWarnings())
                        logAndSetWarningMessages(response);

                    byte[] data = response.getData();
                    if (data != null) {
                        log.info( "Got Data from VOMS server "+Arrays.toString(data) );
                        return new String(data);
                    }
                    else {
                        if (requestOptions.isRequestList()) {
                            // List requests used to put the output in the <data> field.
                            AttributeCertificate ac = VOMSProxyBuilder.buildAC(response.getAC());
                            if (ac != null) {
                                List fqans = ac.getFullyQualifiedAttributes();
                                StringBuilder result = new StringBuilder();
                                if (fqans != null) {
                                    for (int i =0; i < fqans.size(); i++) {
                                        result.append((String)(fqans.get(i)));
                                        result.append("\n");
                                    }
                                }
                                return result.toString();
                            }
                            else
                                return null;
                        }
                        else
                            return null;
                    }
                }
                
                log.error( "Got error response from VOMS server "+serverInfo.compactString() );
                logErrorMessages( response );
                
            }catch(VOMSException e){
                
                log.error(e.getMessage());
                if (log.isDebugEnabled()){
                    log.error(e.getMessage(),e);
                }
                
                if (serverIter.hasNext())
                    continue;
                
                throw(e);
            }
        }
        
        return null;            
    }
    
    public void validateACs(List ACs){
        
        if (ACs.isEmpty())
            throw new VOMSException("Cannot validate an empty list of Attribute Certificates!");
        
        log.debug("AC Validation started at: "+ new Date(  ));
        
        PKIVerifier verifier;
        
        try {
        
            verifier = new PKIVerifier();
        
        } catch ( Exception e ) {
            
            log.error("Error instantiating PKIVerifier: "+e.getMessage());
            
            if (log.isDebugEnabled())
                log.error(e.getMessage(),e);
            throw new VOMSException("Error instantiating PKIVerifier: "+e.getMessage(),e);
            
        }
        
        Iterator i = ACs.iterator();
        
        while(i.hasNext()){
            
            AttributeCertificate ac = (AttributeCertificate)i.next();
            
            if (!verifier.verify( ac ))
                i.remove();    
        }
        
        log.debug("AC Validation ended at: "+ new Date(  ));
        
    }

    public synchronized UserCredentials getVomsProxy(){
        return getVomsProxy( null );
    }

    protected UserCredentials getGridProxy() {
        UserCredentials proxy = VOMSProxyBuilder.buildProxy( userCredentials, proxyLifetime, proxyType, bits);

        warnings = null;

        try{
            saveProxy( proxy );
            return proxy;
        }catch ( FileNotFoundException e ) {
            log.error("Error saving proxy to file "+proxyOutputFile+":"+e.getMessage());
            if (log.isDebugEnabled())
                log.error(e.getMessage(),e);
            
            throw new VOMSException("Error saving proxy to file "+proxyOutputFile+":"+e.getMessage(),e);
        }
    }

    public synchronized UserCredentials getVomsProxy(Collection listOfReqOptions) {
        if (listOfReqOptions == null)
            return getGridProxy();
        
        if (listOfReqOptions.isEmpty())
            throw new VOMSException("No request options specified!");
        
        Iterator i = listOfReqOptions.iterator();
        
        List ACs = new ArrayList();

        warnings = null;
        while (i.hasNext()){
            
            VOMSRequestOptions options = (VOMSRequestOptions)i.next();
            
            if (options.getVoName() == null)
                throw new VOMSException("Please specify a vo name to create a voms proxy.");
            
            AttributeCertificate ac = getVomsAC( options );
            
            ACs.add(ac);
            
        }
        
        validateACs( ACs );
        
        if (ACs.isEmpty())
            throw new VOMSException("AC validation failed!");
        
        log.info( "ACs validation succeded." );
        
        UserCredentials proxy = VOMSProxyBuilder.buildProxy( userCredentials, 
                                                             ACs, proxyLifetime, 
                                                             proxyType, 
                                                             delegationType,
                                                             policyType, this.bits);
        
        try {            
            saveProxy( proxy );
            return proxy;
        } catch ( FileNotFoundException e ) {
            
            log.error("Error saving proxy to file "+proxyOutputFile+":"+e.getMessage());
            if (log.isDebugEnabled())
                log.error(e.getMessage(),e);
            
            throw new VOMSException("Error saving proxy to file "+proxyOutputFile+":"+e.getMessage(),e);
        }
        
        
    }
    
    private void saveProxy(UserCredentials credential) throws FileNotFoundException{
        
        if (proxyOutputFile != null){
            VOMSProxyBuilder.saveProxy( credential, proxyOutputFile );
            log.info( "Proxy saved in :"+proxyOutputFile);
        }
        
    }
    
    private void logErrorMessages(VOMSResponse response){
        
        VOMSErrorMessage[] msgs = response.errorMessages();
        
        for ( int i = 0; i < msgs.length; i++ ) {
            log.error(msgs[i]);
        }        
    }

    private void logAndSetWarningMessages(VOMSResponse response){
        VOMSWarningMessage[] msgs = response.warningMessages();
        setWarnings(msgs);
        for ( int i = 0; i < msgs.length; i++ ) {
            log.warn(msgs[i]);
        }
    }

    private void setWarnings(VOMSWarningMessage[] msgs) {
        warnings = msgs;
    }

    public boolean hasWarnings() {
        return warnings != null;
    }

    public VOMSWarningMessage[] getWarnings() {
        return warnings;
    }

    private VOMSResponse contactServerREST(VOMSServerInfo sInfo, VOMSRequestOptions reqOptions) {
        String url = "https://" + sInfo.getHostName() + ":" + sInfo.getPort() + VOMSRequestFactory.instance().buildRESTRequest(reqOptions);
        VOMSSocket socket;
        VOMSResponse resp = null;

        log.debug("Final URL is: " + url);
        int gridProxyType = sInfo.getGlobusVersionAsInt();
        
        if (gridProxyType > 0)
            socket = VOMSSocket.instance( userCredentials, sInfo.getHostDn(), gridProxyType );
        else
            socket = VOMSSocket.instance( userCredentials, sInfo.getHostDn());
        
        HttpsURLConnection conn = null;

        try {
            SSLSocketFactory factory = socket.getFactory();

            URL vomsUrl = new URL(url);
            conn = (HttpsURLConnection) vomsUrl.openConnection();

            conn.setSSLSocketFactory(factory);
            HostnameVerifier v = conn.getDefaultHostnameVerifier();
            conn.setHostnameVerifier(new GSIVerifier(v, sInfo.getHostDn()));
            conn.connect();
            Object o = conn.getContent();

            resp = VOMSParser.instance().parseResponse((InputStream)o);

        } catch ( Exception e ) {
            
            log.error( "Error connecting to "+sInfo.compactString()+":"+e.getMessage() );

            try {
                log.error("Error code is: " + conn.getResponseCode());

                //                if (conn.getResponseCode() == HttpURLConnection.HTTP_INTERNAL_ERROR) {
                    InputStream is = conn.getErrorStream();
                    resp = VOMSParser.instance().parseResponse(is);
                    return resp;
                    //                }
            } catch (Exception ex) {
                if (log.isDebugEnabled())
                    log.error(e.getMessage(),e);

                throw new VOMSException("Error connecting to "+sInfo.compactString()+":"+ex.getMessage() ,ex);
            }
            // if (log.isDebugEnabled())
            //     log.error(e.getMessage(),e);
            // throw new VOMSException("Error connecting to "+sInfo.compactString()+":"+e.getMessage() ,e);
        }

        return resp;
    }

    protected VOMSResponse contactServer(VOMSServerInfo sInfo, VOMSRequestOptions reqOptions) {
        
        log.info("Contacting server "+sInfo.compactString() );
        VOMSSocket socket;

        VOMSResponse resp = contactServerREST(sInfo, reqOptions);
        if (resp != null) {
            return resp;
        }

        int gridProxyType = sInfo.getGlobusVersionAsInt();
        
        if (gridProxyType > 0)
            socket = VOMSSocket.instance( userCredentials, sInfo.getHostDn(), gridProxyType );
        else
            socket = VOMSSocket.instance( userCredentials, sInfo.getHostDn());
        
        try {
            socket.connect( sInfo.getHostName(), sInfo.getPort());
            
        } catch ( Exception e ) {
            
            log.error( "Error connecting to "+sInfo.compactString()+":"+e.getMessage() );
            
            if (log.isDebugEnabled())
                log.error(e.getMessage(),e);
            throw new VOMSException("Error connecting to "+sInfo.compactString()+":"+e.getMessage() ,e);
            
        } 
        
        VOMSResponse response;
        
        try {

            // re-set the reqOptions voName property to be the true voName recorded by the 
            // sInfo object (the reqOptions voName could actually be an alias rather than 
            // the true vo name).  
            reqOptions.setVoName(sInfo.getVoName()); 
            
            protocol.sendRequest( reqOptions, socket.getOutputStream());
            response = protocol.getResponse( socket.getInputStream() );
            
            socket.close();
            
            
        } catch ( IOException e ) {
            log.error( "Error communicating with server "+sInfo.getHostName()+":"+sInfo.getPort()+":"+e.getMessage() );
            
            if (log.isDebugEnabled())
                log.error(e.getMessage(),e);
            throw new VOMSException("Error communicating with server "+sInfo.getHostName()+":"+sInfo.getPort()+":"+e.getMessage(),e);
        }
        
        return response;
           
    }
    
    public String getProxyOutputFile() {
    
        return proxyOutputFile;
    }
    
    public void setProxyOutputFile( String proxyOutputFile ) {
    
        this.proxyOutputFile = proxyOutputFile;
    }
    
    public int getProxyLifetime() {
    
        return proxyLifetime;
    }
    
    public void setProxyLifetime( int proxyLifetime ) {
    
        this.proxyLifetime = proxyLifetime;
    }

    public int getProxyType() {
    
        return proxyType;
    }
    
    public void setProxyType( int proxyType ) {
    
        this.proxyType = proxyType;
    }

    public int getProxyKeySize() {
        return bits;
    }

    public void setProxyKeySize(int bits) {
        this.bits = bits;
    }

    public String getPolicyType() {
        return policyType;
    }

    public void setPolicyType( String policyType ) {
        this.policyType = policyType;
    }

    public int getDelegationType() {
    
        return delegationType;
    }
    
    public void setDelegationType( int delegationType ) {
    
        this.delegationType = delegationType;
    }    
}

class GSIVerifier implements HostnameVerifier {
    private String name;
    private HostnameVerifier verifier;
    private static final Logger log = Logger.getLogger( GSIVerifier.class );

    static {
        if (Security.getProvider("BC") == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    public GSIVerifier(HostnameVerifier defaultVerifier, String DN) {
        name = DN;
        verifier = defaultVerifier;
    }

    public boolean verify(String hostname, SSLSession session) {
        boolean res = false;
        if (!verifier.verify(hostname, session)) {
            try {
                X509Certificate c = (X509Certificate) session.getPeerCertificates()[0];
                String normal = PKIUtils.getOpenSSLFormatPrincipal(c.getSubjectDN(), false);
                String reversed = PKIUtils.getOpenSSLFormatPrincipal(c.getSubjectDN(), true);
            
                res = PKIUtils.DNCompare(name, normal) || PKIUtils.DNCompare(name, reversed);
                log.debug("result of DN verifier: " + res);

            } catch (SSLPeerUnverifiedException e) {
                log.debug("Unauthenticate peer.  Verify failed.");
                res = false;
            }
        }
        else {
            res = true;
            log.debug("Verified by default verifier");
        }
        return res;
    }
}
