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
    static byte[] PREFIX_SKI = new byte[] { 0x55, 0x1d, 0x0e, 0x04, 0x16, 0x04};

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
    static String getSKI(X509Certificate cert) throws CertificateEncodingException { 
            byte[] bytes = cert.getEncoded();
            int offset = indexOf(bytes, PREFIX_SKI);
            if (offset < 1) { 
                return null;
            }
            offset += PREFIX_SKI.length;
            byte length = bytes[offset];
            byte[] slice = Arrays.copyOfRange(bytes, offset+1, offset+1+length);
            return bytesToHex(slice);
        }    private static String bytesToHex(byte[] bytes) {
        StringBuffer sb = new StringBuffer();
        for (Byte b : bytes) {
            sb.append(String.format("%02X:", b));
        }
        sb.deleteCharAt(sb.length()-1);
        return sb.toString();
    }


  /* from Guava, AL 2.0 licensed */
  /**
   * Returns the start position of the first occurrence of the specified {@code target} within
   * {@code array}, or {@code -1} if there is no such occurrence.
   *
   * <p>More formally, returns the lowest index {@code i} such that {@code Arrays.copyOfRange(array,
   * i, i + target.length)} contains exactly the same elements as {@code target}.
   *
   * @param array the array to search for the sequence {@code target}
   * @param target the array to search for as a sub-sequence of {@code array}
   */
  public static int indexOf(byte[] array, byte[] target) {
    if (target.length == 0) {
      return 0;
    }

    outer:
    for (int i = 0; i < array.length - target.length + 1; i++) {
      for (int j = 0; j < target.length; j++) {
        if (array[i + j] != target[j]) {
          continue outer;
        }
      }
      return i;
    }
    return -1;
  }

    public static int indexOf2(byte[] haystack, byte[] needle)
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