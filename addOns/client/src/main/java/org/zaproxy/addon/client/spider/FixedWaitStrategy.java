/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2026 The ZAP Development Team
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
package org.zaproxy.addon.client.spider;

import java.time.Duration;
import org.zaproxy.addon.client.spider.ClientSpider.WebDriverProcess;

public class FixedWaitStrategy implements ActionWaitStrategy {

    private final long initialLoadTimeMs;
    private final Duration pageLoadWait;
    private final long actionWaitMs;
    private boolean firstAccess = true;

    public FixedWaitStrategy(
            Duration initialLoadTime, Duration pageLoadTime, Duration actionWaitTime) {
        this.initialLoadTimeMs = initialLoadTime.toMillis();
        this.pageLoadWait = pageLoadTime;
        this.actionWaitMs = actionWaitTime.toMillis();
    }

    @Override
    public void configure(WebDriverProcess wdp) {
        wdp.getWebDriver().manage().timeouts().pageLoadTimeout(pageLoadWait);
    }

    @Override
    public boolean waitAfterPageLoad(String url) {
        if (firstAccess) {
            firstAccess = false;
            return sleep(initialLoadTimeMs);
        }
        return true;
    }

    @Override
    public boolean waitAfterAction() {
        return sleep(actionWaitMs);
    }

    private static boolean sleep(long ms) {
        if (ms <= 0) {
            return true;
        }
        try {
            Thread.sleep(ms);
            return true;
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return false;
        }
    }
}
