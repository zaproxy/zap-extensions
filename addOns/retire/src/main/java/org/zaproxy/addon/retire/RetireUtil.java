/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2020 The ZAP Development Team
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.zaproxy.addon.retire;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Formatter;
import org.apache.commons.httpclient.URI;
import org.apache.commons.httpclient.URIException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public final class RetireUtil {

    private static final Logger LOGGER = LogManager.getLogger(RetireUtil.class);

    private RetireUtil() {
        // Utility class
    }

    /*
     * This utility function computes the SHA 1 hash input string
     */
    public static String getHash(byte[] httpbody) {
        try {
            MessageDigest crypt = MessageDigest.getInstance("SHA-1");
            crypt.update(httpbody);
            return byteToHex(crypt.digest());
        } catch (NoSuchAlgorithmException e) {
            LOGGER.warn("Unable to generate Hash.", e);
            return "";
        }
    }

    /*
     * This utility function computes input byte array to a hex string
     */
    private static String byteToHex(byte[] hash) {
        Formatter formatter = new Formatter();
        for (byte b : hash) {
            formatter.format("%02x", b);
        }
        String result = formatter.toString();
        formatter.close();
        return result;
    }

    /*
     * This utility function retrieves the JS file name from passed URI.
     */
    public static String getFileName(URI uri) {
        try {
            return uri.getName();
        } catch (URIException e) {
            LOGGER.warn("There was an error parsing the URI", e);
        }
        return null;
    }

    /*
     * This utility function determines if
     *  version1(of a particular JS library) is >= version2(of a particular JS library)
     */
    public static boolean isAtOrAbove(String version1, String version2) {
        String[] v1 = version1.split("[\\.-]");
        String[] v2 = version2.split("[\\.-]");
        int l = v1.length > v2.length ? v1.length : v2.length;
        for (int i = 0; i < l; i++) {
            String v1Part = v1.length > i ? v1[i] : "0";
            String v2part = v2.length > i ? v2[i] : "0";
            boolean v1IsNumber = isNumber(v1Part);
            boolean v2IsNumber = isNumber(v2part);

            // if either of v1 or v2 is string
            if (v1IsNumber != v2IsNumber) {
                return v1IsNumber;
            }

            // if both v1 and v2 are strings
            if (!v1IsNumber && !v2IsNumber) {
                return v1Part.compareTo(v2part) > 0;
            }

            // if both are numbers
            if (Integer.parseInt(v1Part) < Integer.parseInt(v2part)) {
                return false;
            }
            if (Integer.parseInt(v1Part) > Integer.parseInt(v2part)) {
                return true;
            }
        }
        return true;
    }

    /*
     * This utility function determines if given input string is numeric.
     */
    static boolean isNumber(String num) {
        return num.matches("^[0-9]+$");
    }
}
