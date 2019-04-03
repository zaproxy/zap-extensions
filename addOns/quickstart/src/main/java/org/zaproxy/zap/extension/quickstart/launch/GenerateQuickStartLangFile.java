/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2018 The ZAP development team
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
package org.zaproxy.zap.extension.quickstart.launch;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FilenameFilter;
import java.io.IOException;
import java.util.Properties;

public class GenerateQuickStartLangFile {

    private static final String I18N_TAG = "quickstart.launch.browser.html";
    private static final String LOGO_HTML = "<img src=\"https://github.com/zaproxy/zaproxy/raw/develop/src/resource/zap128x128.png\"\n"
            + "  style=\"float:right;width:128px;height:128px;\">";

    public GenerateQuickStartLangFile() {
    }

    private static File[] getLanguageFiles(File dir) {
        FilenameFilter filter = new FilenameFilter() {

            @Override
            public boolean accept(File dir, String name) {
                return name.startsWith("Messages_") && name.endsWith(".properties");
            }
        };
        return dir.listFiles(filter);
    }

    private static String getFirstLine(String str) {
        if (str == null) {
            return null;
        }
        int idx = str.indexOf("\n");
        if (idx < 0) {
            return str;
        }
        return str.substring(0, idx);
    }

    private static boolean printLangFile(File dir) {
        if (!dir.isDirectory()) {
            // Dont log an error in case we retry other directories
            return false;
        }
        File defaultLangFile = new File(dir, "Messages.properties");
        if (!defaultLangFile.isFile()) {
            System.err.println("Failed to find default language file: " + defaultLangFile.getAbsolutePath());
            return false;
        }
        File[] files = getLanguageFiles(dir);
        if (files.length == 0) {
            System.err.println("Failed to find not default language files in: " + dir.getAbsolutePath());
            return false;
        }

        Properties props = new Properties();
        try {
            loadProperties(props, defaultLangFile);
            String enStr = props.getProperty(I18N_TAG);
            if (enStr == null) {
                System.err.println("Failed to read the default tag: " + I18N_TAG);
                return false;
            }
            String enStr1stLine = getFirstLine(enStr);
            // Output the default translation
            System.out.print(ExtensionQuickStartLaunch.PAGE_LOCALE_SEPARATOR);
            System.out.print(ExtensionQuickStartLaunch.PAGE_LOCALE_PREFIX);
            System.out.print(ExtensionQuickStartLaunch.PAGE_LOCALE_DEFAULT);
            System.out.println(ExtensionQuickStartLaunch.PAGE_LOCALE_POSTFIX);
            System.out.println(LOGO_HTML);
            System.out.println(enStr);

            for (File f : files) {
                props.clear();
                loadProperties(props, f);
                String i18nStr = props.getProperty(I18N_TAG);
                // Just check the first line - some translations have different newlines
                if (i18nStr != null && !enStr1stLine.equals(getFirstLine(i18nStr))) {
                    // Its been translated
                    String filename = f.getName();
                    String locale = filename.substring(filename.indexOf("_") + 1, filename.indexOf("."));

                    System.out.print(ExtensionQuickStartLaunch.PAGE_LOCALE_SEPARATOR);
                    System.out.print(ExtensionQuickStartLaunch.PAGE_LOCALE_PREFIX);
                    System.out.print(locale);
                    System.out.println(ExtensionQuickStartLaunch.PAGE_LOCALE_POSTFIX);
                    System.out.println(LOGO_HTML);
                    System.out.println(i18nStr);
                }
            }

        } catch (FileNotFoundException e) {
            System.err.println("Exception: " + e.getMessage());
            return false;
        } catch (IOException e) {
            System.err.println("Exception: " + e.getMessage());
            return false;
        }

        return true;
    }

    private static void loadProperties(Properties props, File file) throws IOException {
        try (FileInputStream fis = new FileInputStream(file)) {
            props.load(fis);
        }
    }

    public static void main(String[] params) {
        File f = new File("src/org/zaproxy/zap/extension/quickstart/resources");
        if (!printLangFile(f)) {
            System.err.println("Failed to find language files in " + f.getAbsolutePath());
        }
    }
}
