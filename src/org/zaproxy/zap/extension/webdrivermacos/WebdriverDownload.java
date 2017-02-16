/*
 * Zed Attack Proxy (ZAP) and its related class files.
 * 
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 * 
 * Copyright 2017 The ZAP Development Team
 *  
 * Licensed under the Apache License, Version 2.0 (the "License"); 
 * you may not use this file except in compliance with the License. 
 * You may obtain a copy of the License at 
 * 
 *   http://www.apache.org/licenses/LICENSE-2.0 
 *   
 * Unless required by applicable law or agreed to in writing, software 
 * distributed under the License is distributed on an "AS IS" BASIS, 
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. 
 * See the License for the specific language governing permissions and 
 * limitations under the License. 
 */
package org.zaproxy.zap.extension.webdrivermacos;

import java.io.File;
import java.io.FileOutputStream;
import java.net.URL;
import java.nio.channels.Channels;
import java.nio.channels.ReadableByteChannel;
import java.nio.file.Paths;

public class WebdriverDownload {

    /**
     * The webdriver files are help in the zap-libs repo to prevent space problems in this one.
     * The zap-libs repo contains tasks for downloading the files from their orriginal locations.
     * The code will need to be changed and rerun whenever new versions of the webdrivers become available.
     * 
     * @param args
     */
	public static void main(String[] args) {
        downloadDriver(
                "https://github.com/zaproxy/zap-libs/raw/master/files/webdriver/macos/64/geckodriver",
                "files/webdriver/macos/64/geckodriver");
        downloadDriver(
                "https://github.com/zaproxy/zap-libs/raw/master/files/webdriver/macos/64/chromedriver",
                "files/webdriver/macos/64/chromedriver");
    }
    
    private static void downloadDriver(String urlStr, String destFile) {
        String baseDir = "src/";
        if (Paths.get("").toAbsolutePath().toString().endsWith("build")) {
            // Likely to be being invoked from the build script
            baseDir = "../src/";
        }
        File dest = new File(
                baseDir + WebdriverDownload.class.getPackage().getName().replace(".", "/") + "/" + destFile);
        if (dest.exists()) {
            System.out.println("Already exists: " + dest.getAbsolutePath());
            return;
        }
        File parent = dest.getParentFile();
        if (!parent.exists() && !parent.mkdirs()) {
            System.out.println("Failed to create directory : " + dest.getParentFile().getAbsolutePath());
        }
        
        try (FileOutputStream fos = new FileOutputStream(dest)) {
            URL website = new URL(urlStr);
            ReadableByteChannel rbc = Channels.newChannel(website.openStream());
            fos.getChannel().transferFrom(rbc, 0, Long.MAX_VALUE);
            System.out.println("Updated: " + dest.getAbsolutePath());
        } catch (Exception e) {
            e.printStackTrace();
            System.exit(1);
        }
    }
}
