/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2025 The ZAP Development Team
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
package org.zaproxy.addon.authhelper.internal;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.openqa.selenium.WebDriver;
import org.zaproxy.zest.core.v1.ZestClient;
import org.zaproxy.zest.core.v1.ZestClientFailException;
import org.zaproxy.zest.core.v1.ZestClientLaunch;
import org.zaproxy.zest.core.v1.ZestClientWindowClose;
import org.zaproxy.zest.core.v1.ZestScript;
import org.zaproxy.zest.impl.ZestBasicRunner;

public class ZestAuthRunner extends ZestBasicRunner {

    private static final Logger LOGGER = LogManager.getLogger(ZestAuthRunner.class);

    private WebDriver webDriver;

    public ZestAuthRunner() {
        super();
    }

    public void setWebDriver(WebDriver webDriver) {
        this.webDriver = webDriver;
    }

    @Override
    public String handleClient(ZestScript script, ZestClient client)
            throws ZestClientFailException {
        LOGGER.debug("handleClient {}", client.getClass().getCanonicalName());

        if (client instanceof ZestClientLaunch clientLaunch) {
            this.addWebDriver(clientLaunch.getWindowHandle(), webDriver);
            LOGGER.debug(
                    "handleClient client launch, registering {}", clientLaunch.getWindowHandle());
            this.webDriver.get(clientLaunch.getUrl());
            return clientLaunch.getWindowHandle();
        } else if (client instanceof ZestClientWindowClose) {
            // We don't want to close the window as the browser lifecycle is managed externally
            return null;
        }
        return super.handleClient(script, client);
    }
}
