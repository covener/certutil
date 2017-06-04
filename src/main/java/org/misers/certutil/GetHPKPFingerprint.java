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

import java.io.FileInputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;
import org.apache.commons.codec.binary.Base64;

/** 
 * @author covener 
 */
public class GetHPKPFingerprint {
    static boolean debug = false;
    private String db, label;
    
    public GetHPKPFingerprint(String db, String label) { 
        this.db = db;
        this.label = label;
        try {
            @SuppressWarnings("unchecked")
            Class<java.security.Provider> cmsclass = (Class<Provider>) Class.forName("com.ibm.security.cmskeystore.CMSProvider");
            Security.addProvider(cmsclass.newInstance());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    public static String getThumbPrint(Certificate cert) 
            throws NoSuchAlgorithmException, CertificateEncodingException, javax.security.cert.CertificateEncodingException {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] der = cert.getPublicKey().getEncoded();
            md.update(der);
            byte[] digest = md.digest();
            return Base64.encodeBase64String(digest);
    }
            
    private static Certificate getCertificate(String db, String pw, String label) throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException { 
        KeyStore ks = KeyStore.getInstance("IBMCMSKS");
        FileInputStream in = new FileInputStream(db);
        ks.load(in, pw.toCharArray());
        return ks.getCertificate(label);
    }
    
    private String getPIN() throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException, javax.security.cert.CertificateEncodingException {
        System.out.println("Please enter the password for keystore " + this.db + "\n");
        String pw = new String(System.console().readPassword());

        return getThumbPrint(getCertificate(this.db, pw, this.label));
    }
    
    public static void main(String[] args) throws Exception { 

        CommandLineParser parser = new DefaultParser();
        CommandLine line = null;
        Options options = new Options();
        
        options.addOption("db", true, "path to CMS KDB B");
        options.addOption("label", true, "label of cert in KDB");
        options.addOption("debug", false, "debug");
        options.addOption("h", false, "help");

        HelpFormatter formatter = new HelpFormatter();
    
        try {
            line = parser.parse(options, args);
        } catch (ParseException exp) {
            System.out.println(exp);
            formatter.printHelp("GetHPKPFingerprint", options);
            return;
        }
        
        if (line.hasOption("debug")) debug = true;
        
        if (!line.hasOption("db") || !line.hasOption("label")) { 
            usage();
        }
        
        GetHPKPFingerprint retriever = new GetHPKPFingerprint(line.getOptionValue("db"), line.getOptionValue("label"));
        System.out.println(retriever.getPIN());
    }

    private static void usage() {
        System.err.println("Required Parameters: -db /path/to/cms.kdb -label label-name");
        System.exit(1);
    }

}
