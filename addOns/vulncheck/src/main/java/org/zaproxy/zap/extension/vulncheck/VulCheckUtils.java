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
package org.zaproxy.zap.extension.vulncheck;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.ConnectException;
import java.net.HttpURLConnection;
import java.net.URL;

public class VulCheckUtils {

    /**
     * TODO: extend it to check url+/blabla/+filepath, that extended call this not extended one like
     * this : checkIfExist(url) with one argument
     *
     * <p>Answer if a given file exists in a given webapp
     *
     * @return true if the file exists, false else
     * @param appUrl
     * @param filePath
     * @throws IOException
     */
    public static boolean checkIfExist(URL appUrl, String filePath) throws IOException {
        URL completeUrl = new URL(appUrl.toString() + filePath);
        // System.out.println("-->"+completeUrl.toString());
        HttpURLConnection con = (HttpURLConnection) completeUrl.openConnection();
        con.setRequestMethod("HEAD");
        // System.out.println(con.getResponseCode());
        if (con.getResponseCode() == HttpURLConnection.HTTP_OK) {
            // System.out.println("yes");
            return true;
        }
        return false;
    }

    /**
     * **************** pending
     *
     * <p>Answer if a given url exists (server code 200)
     *
     * @return true if the file exists, false else
     * @param appUrl
     * @param filePath
     * @throws IOException
     */
    public static boolean checkIfExist(URL url) throws IOException {

        // System.out.println("-->"+completeUrl.toString());
        HttpURLConnection con = (HttpURLConnection) url.openConnection();
        con.setRequestMethod("HEAD");
        // System.out.println(con.getResponseCode());
        int responseCode = -917;
        while (responseCode == -917) {
            try {
                responseCode = con.getResponseCode();
            } catch (ConnectException e) {
                System.out.println("Retrying to connect");
            }
        }
        if (responseCode == HttpURLConnection.HTTP_OK) {
            // System.out.println("yes");
            return true;
        }
        return false;
    }

    /**
     * @param url
     * @return
     * @throws IOException
     */
    public static InputStream getFileFromUrl(URL url) throws IOException {

        InputStream is = null;
        try {
            is = url.openStream();
            File file = new File(url.getPath());
            // System.out.println("filename = "+file.getName());
            FileOutputStream out = new FileOutputStream(file.getName());
        } catch (Exception e) {
            // e.printStackTrace();
        }

        /** some stuff to do with 'out' */
        return is;
    }
}
