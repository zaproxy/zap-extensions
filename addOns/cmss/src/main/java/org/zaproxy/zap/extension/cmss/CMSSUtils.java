/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2013 The ZAP Development Team
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
package org.zaproxy.zap.extension.cmss;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.net.URL;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.codec.digest.DigestUtils;

public class CMSSUtils {

    public static InputStream getFileFromUrl(URL url) throws IOException {
        InputStream is = null;
        try {
            is = url.openStream();
            File file = new File(url.getPath());
            FileOutputStream out = new FileOutputStream(file.getName());
        } catch (Exception e) {
        }
        return is;
    }

    public static String checkSumApacheCommons(InputStream is) {
        String checksum = null;
        try {
            checksum = DigestUtils.md5Hex(is);
        } catch (IOException e) {
            e.printStackTrace();
        }
        return checksum;
    }

    public static String checkUrlContentChecksums(URL url) throws IOException {
        return checkSumApacheCommons(getFileFromUrl(url));
    }

    public static String checksum(byte[] octets)
            throws UnsupportedEncodingException, NoSuchAlgorithmException {
        final MessageDigest messageDigest = MessageDigest.getInstance("MD5");
        messageDigest.reset();
        messageDigest.update(octets);
        final byte[] resultByte = messageDigest.digest();
        return new String(Hex.encodeHex(resultByte));
    }
}
