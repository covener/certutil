/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements. See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership. The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.misers.certutil;

/**
 * @author covener
 */
import java.io.BufferedOutputStream;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.URISyntaxException;
import java.security.KeyStore;
import java.security.Provider;
import java.security.Security;
import java.util.Arrays;

import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;

/**
 * Retrieves signer cert from a host:port, and optionally adds it in a KDB or JKS file
 * @author covener
 *
 */
public class RetrieveSigner {
    static boolean debug = false;
    
    public RetrieveSigner() { 
    
    }
    
    private void writeCert(X509Certificate cert, String fname) throws Exception {
        FileOutputStream fos = null;
   
        try { 
            fos = new FileOutputStream(fname);
        }
        catch (FileNotFoundException fnf) { 
            System.err.println("Couldn't write to temp file " + fname + ", " + fnf.toString());
            throw fnf;
        }
        
        BufferedOutputStream bos = new BufferedOutputStream(fos);
        try { 
            byte[] bytes = cert.getEncoded();
            bos.write(bytes);
        } catch (CertificateEncodingException e) {
            e.printStackTrace();
            throw e;
        }
        finally { 
            bos.close();
        }
    }
    public X509Certificate getCert(String host, int port) throws Exception {
        javax.net.ssl.TrustManager[] trustAllCerts = new javax.net.ssl.TrustManager[1];
        javax.net.ssl.TrustManager tm = new RetrieveSigner.LenientTrustManager();
        trustAllCerts[0] = tm;

        System.out.println("Getting signer for " + host + ":" + port);
        javax.net.ssl.SSLContext sc = null;
        sc = javax.net.ssl.SSLContext.getInstance("SSL");

        sc.init(null, trustAllCerts, null);
        SSLSocket socket = (SSLSocket) sc.getSocketFactory().createSocket(host, port);

        try { 
            socket.startHandshake();
        }
        catch (Exception e) { 
            socket.close();
            System.out.println("Got an exception with 'TLS', trying 'TLSv1.2'");
            sc = javax.net.ssl.SSLContext.getInstance("TLSv1.2");
            sc.init(null, trustAllCerts, null);
            socket = (SSLSocket) sc.getSocketFactory().createSocket(host, port);
            socket.startHandshake();
        }
        socket.close();
        SSLSession sess = socket.getSession();
        X509Certificate[] certs = (X509Certificate[]) sess.getPeerCertificates();
        for (X509Certificate cert : certs) { 
            if (cert.getSubjectDN().equals(cert.getIssuerDN())) {
               System.out.println("Got signer, Subject=[" + cert.getSubjectDN() + "]");
               return cert;
            }
        }
        System.err.println("The target server does not send its root certificate as part of the handshake. You'll have to grab the CA certificate elsehwere and 'add' it with gskcapicmd");
       
        int i = 0;
        for (X509Certificate cert : certs) { 
           System.err.println("Depth " + i++);
           System.err.println("  Subject: " + cert.getSubjectDN());
           System.err.println("  Issuer : " + cert.getIssuerDN());
           System.err.println("  AKI is " + KeyIdFinder.getAKI(cert));
           
        }
        System.exit(1);
        return null;
    }
    
    public void updateKeystore (X509Certificate cert, String label, String ks, boolean checkonly, String pw) throws Exception {
        OutputStream os = null;
        InputStream in = null;
        KeyStore keystore = null;
        boolean isKDB = ks.endsWith(".kdb");
        boolean isPKCS12 = ks.endsWith(".p12") || ks.endsWith(".pfx");
        String type = KeyStore.getDefaultType();
        if (isKDB) {  
            type = "IBMCMSKS";
        }
        else if (isPKCS12) { 
            type = "PKCS12";
        }

        if (debug) { 
            System.err.println("pw is " + pw);
        }
        if (isKDB) { 
            Class<java.security.Provider> cmsclass = null;
            try { 
                cmsclass = (Class<Provider>) Class.forName("com.ibm.security.cmskeystore.CMSProvider");
            }
            catch (Exception e) { 
                System.err.println("Error loading CMS (*.kdb) provider, use an IBM Java SDK!\n" + e.toString());
                return;
            }
            Security.addProvider(cmsclass.newInstance());
        }
        
        /* Step one, read the old KDB */
        try { 
            if (pw == null) { 
                if (isKDB || isPKCS12)  {
                    String stashFile = ks.replaceAll("\\.kdb", ".sth");
                    stashFile = stashFile.replaceAll("\\.p12", ".sth");
                    stashFile = stashFile.replaceAll("\\.pfx", ".sth");
                    if (debug) { 
                        System.err.println("Opening stash file " + stashFile);
                    }
                }
                if (pw == null) { 
                    System.out.println("Please enter the password for keystore \n" + ks);
                    pw = new String(System.console().readPassword());
                }
            }            
            keystore = KeyStore.getInstance(type);
            in = new FileInputStream(ks);
            keystore.load(in, pw.toCharArray());
        } catch (Exception e) {
            System.err.println("Error loading " + ks + " (kdb unchanged) : " + e.getMessage());
            e.printStackTrace();
            throw e;
        }
        finally { 
            if (in != null)
                try {
                    in.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
        }
        
        System.out.println("Checking keystore " + ks + " for existing signer " + cert.getSubjectDN() + " ...");
        String alias = keystore.getCertificateAlias(cert);
        
        if (alias != null) { 
            System.out.println("Requested signer already exists with label '" + alias + "'");
            return;
        }
        else { 
            if (checkonly) { 
                System.out.println("Requested signer not found");
                return;
            }
        }
            
        System.out.println("Updating keystore " + ks + " ...");
        
        keystore.setCertificateEntry(label, cert);
        
        /* Step two, write a new updated KDB */
        String tmpks = ks + ".tmp";

        try { 
            os = new FileOutputStream(ks + ".tmp");
            keystore.store(os, pw.toCharArray());
        } catch (Exception  e) {
            System.err.println("Error writing out temporary KDB w/ updates: " + e.getMessage());
            e.printStackTrace();
            throw e;
        }
        finally { 
            if (os != null)
                try {
                    os.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
        }
        
        /* Step Three, replace the old KDB with the new KDB */
        
        try { 
            File old = new File(ks);
            File repl = new File(tmpks);
            old.delete();
            repl.renameTo(old);
        }
        catch (Exception e) { 
            System.err.println("Error moving updated KDB into place: " + e.getMessage());
            e.printStackTrace();
            throw e;
        }
        
        System.out.println("Updated keystore");
    }
    
    private static java.security.cert.X509Certificate convert(javax.security.cert.X509Certificate cert) {
        try {
            byte[] encoded = cert.getEncoded();
            ByteArrayInputStream bis = new ByteArrayInputStream(encoded);
            java.security.cert.CertificateFactory cf
                = java.security.cert.CertificateFactory.getInstance("X.509");
            return (java.security.cert.X509Certificate)cf.generateCertificate(bis);
        } catch (java.security.cert.CertificateEncodingException e) {
        } catch (javax.security.cert.CertificateEncodingException e) {
        } catch (java.security.cert.CertificateException e) {
        }
        return null;
    }

    // Converts to javax.security
    private static javax.security.cert.X509Certificate convert(java.security.cert.X509Certificate cert) {
        try {
            byte[] encoded = cert.getEncoded();
            return javax.security.cert.X509Certificate.getInstance(encoded);
        } catch (java.security.cert.CertificateEncodingException e) {
        } catch (javax.security.cert.CertificateEncodingException e) {
        } catch (javax.security.cert.CertificateException e) {
        }
        return null;
    }
    
    private static void usage(Options options) throws URISyntaxException { 
        File myjar =  new File(GetHPKPFingerprint.class.getProtectionDomain().getCodeSource().getLocation().toURI().getPath());
        HelpFormatter formatter = new HelpFormatter();
        
        formatter.printHelp("RetrieveSigner host port [keystore-to-update] [options]\n", options);
        System.err.println("\n\nExamples:\n\tjava -jar " + myjar + " w3.ibm.com 443 /tmp/key.kdb");
        System.err.println("\tjava -jar " + myjar + " --host w3.ibm.com --port 443 --db /tmp/key.kdb");
        System.exit(1);;
    }
    
    private class LenientTrustManager implements javax.net.ssl.TrustManager, javax.net.ssl.X509TrustManager {
        public java.security.cert.X509Certificate[] getAcceptedIssuers() {
            return null;
        }
        public boolean isServerTrusted(
            java.security.cert.X509Certificate[] certs) {
            return true;
        }
        public boolean isClientTrusted(
            java.security.cert.X509Certificate[] certs) {
            return true;
        }
        public void checkServerTrusted(
            java.security.cert.X509Certificate[] certs,
            String authType)
            throws java.security.cert.CertificateException {
            return;
        }
        public void checkClientTrusted(
            java.security.cert.X509Certificate[] certs,
            String authType)
            throws java.security.cert.CertificateException {
            return;
        }
    }
    
    public static void main(String[] args) throws Exception { 

        CommandLineParser parser = new DefaultParser();
        CommandLine line = null;
        Options options = new Options();
        
        options.addOption( Option.builder("host").longOpt("host").required(true).
                hasArg().build());
        options.addOption( Option.builder("d").longOpt("db").required(true).
                hasArg().build());
        options.addOption( Option.builder("p").longOpt("port").required(true).
                hasArg().build());
        options.addOption( Option.builder("P").longOpt("password").required(false).
                hasArg().build());

        options.addOption("check", false, "just check the keystore");
        options.addOption("h", false, "help");

        if (args.length < 1) {
            usage(options);
        }
        
        /* Convert old/simple syntax to getopt syntax */

        int newlength = args.length;
        if (!args[0].startsWith("-")) { 
            newlength++;
            if (args.length > 1 && !args[1].startsWith("-")) { 
                newlength++;
            }
            if (args.length > 2 && !args[2].startsWith("-")) { 
                newlength++;
            }
        }        
        String[] newargs = new String[newlength];
        
        int skip = 0;
        int curnewargs = 0;
        if (!args[0].startsWith("-")) { 
            System.err.println("first - " + args[0]);
            skip++;
            newargs[curnewargs++] = "--host";
            newargs[curnewargs++] = args[0];
        
            if (args.length > 1 && !args[1].startsWith("-")) { 
                skip++;
                newargs[curnewargs++] = "--port";
                newargs[curnewargs++] = args[1];
            }
            if (args.length > 2 && !args[2].startsWith("-")) {     
                skip++;
                newargs[curnewargs++] = "--db";
                newargs[curnewargs++] = args[2];
            }
        }        
        while(skip < args.length) { 
            newargs[curnewargs++] = args[skip++];
        }

        try {
            line = parser.parse(options, newargs);
        } catch (ParseException exp) {
            System.out.println(exp);
            HelpFormatter formatter = new HelpFormatter();
            formatter.printHelp("RetrieveSigner", options);
            return;
        }
        
        if (line.hasOption("debug")) debug = true;
        if (debug) { 
            System.err.println("Original args: " + Arrays.toString(args));
            System.err.println("Rewritten args: "+ Arrays.toString(newargs));
            
        }
        if (line.getOptionValue("host") == null || line.getOptionValue("port") == null) { 
            System.out.println("--host and --port are required");
            System.exit(1);
        }

        if (debug) { 
            System.err.println("Retrieving signer from " + line.getOptionValue("host") + ":" + line.getOptionValue("port"));
        }
        
        RetrieveSigner retriever = new RetrieveSigner();
        X509Certificate cert = retriever.getCert(line.getOptionValue("host"), Integer.parseInt(line.getOptionValue("port")));


        File tmp = File.createTempFile("temp",".der");
        retriever.writeCert(cert, tmp.getAbsolutePath());

        String thePass = line.getOptionValue("password");
        
        if (line.hasOption("db")) {  
           retriever.updateKeystore(cert, 
                    cert.getSubjectDN().toString(), 
                    line.getOptionValue("db"), 
                    line.hasOption("check"), 
                    thePass);
            tmp.delete();
        }
        else { 
            System.out.println("Wrote certificate to " + tmp.getAbsolutePath());
        }
    }
}
