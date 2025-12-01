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

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.stream.Stream;
import javax.swing.filechooser.FileFilter;
import org.apache.commons.lang3.Strings;
import org.parosproxy.paros.Constant;
import org.zaproxy.zap.utils.Enableable;

public class BrowserExtension extends Enableable {

    private static final String FIREFOX_EXT = "xpi";
    private static final String MANIFEST_FILE = "manifest.json";

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
        if (hasFileExtension(path, FIREFOX_EXT)) {
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

    public static BrowserExtensionFileFilter getFileFilter() {
        return new BrowserExtensionFileFilter();
    }

    public static boolean isBrowserExtension(Path path) {
        if (path == null) {
            return false;
        }

        if (hasFileExtension(path, FIREFOX_EXT)) {
            return true;
        }

        if (!Files.isDirectory(path)) {
            return false;
        }

        try (Stream<Path> stream = Files.walk(path, 1)) {
            return stream.anyMatch(e -> MANIFEST_FILE.equals(e.getFileName().toString()));
        } catch (IOException ignore) {
            // Nothing to do.
        }
        return false;
    }

    private static boolean hasFileExtension(Path path, String extension) {
        return Strings.CI.endsWith(path.getFileName().toString(), extension);
    }

    public static class BrowserExtensionFileFilter extends FileFilter {

        @Override
        public boolean accept(File f) {
            return f.isDirectory()
                    || hasFileExtension(f.toPath(), FIREFOX_EXT)
                    || MANIFEST_FILE.equals(f.getName());
        }

        @Override
        public String getDescription() {
            return Constant.messages.getString("selenium.browser.extentions.filefilter");
        }

        public File getBrowserExtensionPath(File f) {
            if (f == null) {
                return null;
            }

            if (isBrowserExtension(f.toPath())) {
                return f;
            }

            if (MANIFEST_FILE.equals(f.getName())) {
                return f.getParentFile();
            }

            return null;
        }
    }
}
