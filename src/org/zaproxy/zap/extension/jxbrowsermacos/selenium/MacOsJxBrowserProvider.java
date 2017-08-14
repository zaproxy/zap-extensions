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
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.zaproxy.zap.extension.jxbrowsermacos.selenium;

import java.net.InetAddress;
import java.net.ServerSocket;

import org.openqa.selenium.WebDriverException;
import org.zaproxy.zap.extension.selenium.SingleWebDriverProvider;

/**
 * A {@link SingleWebDriverProvider} for JxBrowser on MacOS.
 */
public class MacOsJxBrowserProvider extends JxBrowserProvider {

    private Integer chromePort;

    @Override
    protected int getFreePort() {
        // Reuse the same port, as the JxBrowser/Chrome process tends to live longer on macOS.
        if (chromePort == null) {
            try (ServerSocket socket = new ServerSocket(0, 400, InetAddress.getByName("localhost"))) {
                chromePort = socket.getLocalPort();
            } catch (Exception e) {
                throw new WebDriverException(e);
            }
        }
        return chromePort;
    }
}
