/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2021 The ZAP Development Team
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
package org.zaproxy.zap.extension.selenium;

import java.nio.file.Path;
import java.util.Locale;
import javax.swing.filechooser.FileNameExtensionFilter;
import org.parosproxy.paros.Constant;
import org.zaproxy.zap.utils.Enableable;

public class BrowserExtension extends Enableable {

    private static final String FIREFOX_EXT = "xpi";
    private static final String CHROME_EXT = "crx";
    private Path path;
    private Browser browser;

    public BrowserExtension(Path path, boolean enabled, Browser browser) {
        super(enabled);
        this.path = path;
        this.browser = browser;
    }

    public BrowserExtension(Path path) {
        super(true);
        this.path = path;
        String nameLc = path.toString().toLowerCase(Locale.ROOT);
        if (nameLc.endsWith(FIREFOX_EXT)) {
            this.browser = Browser.FIREFOX;
        } else {
            this.browser = Browser.CHROME;
        }
    }

    public BrowserExtension(BrowserExtension ext) {
        super();
        if (ext != null) {
            this.setEnabled(ext.isEnabled());
            this.setPath(ext.getPath());
            this.setBrowser(ext.getBrowser());
        }
    }

    public Path getPath() {
        return path;
    }

    public void setPath(Path path) {
        this.path = path;
    }

    public Browser getBrowser() {
        return browser;
    }

    public void setBrowser(Browser browser) {
        this.browser = browser;
    }

    public static FileNameExtensionFilter getFileNameExtensionFilter() {
        return new FileNameExtensionFilter(
                Constant.messages.getString("selenium.browser.extentions.filefilter"),
                FIREFOX_EXT,
                CHROME_EXT);
    }

    public static boolean isBrowserExtension(Path path) {
        if (path == null) {
            return false;
        }
        String nameLc = path.toString().toLowerCase(Locale.ROOT);
        return nameLc.endsWith(FIREFOX_EXT) || nameLc.endsWith(CHROME_EXT);
    }
}
