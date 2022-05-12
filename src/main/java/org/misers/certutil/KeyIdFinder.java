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

import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Arrays;

public class KeyIdFinder { 

    static byte[] PREFIX_AKI = new byte[] { 0x55, 0x1d, 0x23, 0x04, 0x18, 0x30};

    static String getAKI(X509Certificate cert) throws CertificateEncodingException { 
        byte[] bytes = cert.getEncoded();
        int offset = indexOf(bytes, PREFIX_AKI);
        if (offset < 1) { 
            return null;
        }
        offset += PREFIX_AKI.length;
        offset +=2; // skip to length
        byte length = bytes[offset];
        byte[] slice = Arrays.copyOfRange(bytes, offset+1, offset+1+length);
        return bytesToHex(slice);
    }


    private static final char[] HEX_ARRAY = "0123456789ABCDEF".toCharArray();
    private static String bytesToHex(byte[] bytes) {
        char[] hexChars = new char[bytes.length * 3];
        for (int j = 0; j < bytes.length; j++) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 3] = HEX_ARRAY[v >>> 4];
            hexChars[j * 3 + 1] = HEX_ARRAY[v & 0x0F];
            hexChars[j * 3 + 2] = ':';
        }
        String s = new String(hexChars);
        return s.substring(0, s.length() - 1);
    }

    public static int indexOf(byte[] haystack, byte[] needle)
    {
        // needle is null or empty
        if (needle == null || needle.length == 0)
            return 0;

        // haystack is null, or haystack's length is less than that of needle
        if (haystack == null || needle.length > haystack.length)
            return -1;

        // pre construct failure array for needle pattern
        int[] failure = new int[needle.length];
        int n = needle.length;
        failure[0] = -1;
        for (int j = 1; j < n; j++)
        {
            int i = failure[j - 1];
            while ((needle[j] != needle[i + 1]) && i >= 0)
                i = failure[i];
            if (needle[j] == needle[i + 1])
                failure[j] = i + 1;
            else
                failure[j] = -1;
        }

        // find match
        int i = 0, j = 0;
        int haystackLen = haystack.length;
        int needleLen = needle.length;
        while (i < haystackLen && j < needleLen)
        {
            if (haystack[i] == needle[j])
            {
                i++;
                j++;
            }
            else if (j == 0)
                i++;
            else
                j = failure[j - 1] + 1;
        }
        return ((j == needleLen) ? (i - needleLen) : -1);
    }    
}