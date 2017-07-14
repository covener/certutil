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

import java.io.File;
import java.net.URISyntaxException;
import java.util.LinkedList;
import java.util.List;

/**
 * 
 * @author covener
 */
public class CertUtil {

    public CertUtil() {
        
    }
    
    private static void usage() throws URISyntaxException { 
        File myjar =  new File(CertUtil.class.getProtectionDomain().getCodeSource().getLocation().toURI().getPath());
        System.err.println("java -jar " + myjar + " RetrieveSigner | GetPIN | Torture");
        System.exit(1);
    }
    
    private static String[] shift(String[] args) { 
        List<String> argList = new LinkedList<String>();
        for (int i = 1; i < args.length; i++) { 
            argList.add(args[i]);
        }
        return argList.toArray(new String[args.length - 1]);    
     }
    
    public static void main(String[] args) throws Exception { 
        if (args.length == 0) usage();
        String op = args[0];
        String[] supplicantArgs = shift(args);
        
        if (op.equals("RetrieveSigner")) { 
            RetrieveSigner.main(supplicantArgs);
        }
        else if(op.equals("GetPIN")) { 
            GetHPKPFingerprint.main(supplicantArgs);
        }
        else if(op.equals("Torture")) { 
            SSLClientHTTPSAdvisorLike.main(supplicantArgs);
        }
        else { 
            usage();
        }
    }
}
