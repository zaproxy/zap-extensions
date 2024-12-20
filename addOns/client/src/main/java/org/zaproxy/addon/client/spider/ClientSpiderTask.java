/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2023 The ZAP Development Team
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
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.openqa.selenium.WebDriver;

public class ClientSpiderTask implements Runnable {

    private static final Logger LOGGER = LogManager.getLogger(ClientSpiderTask.class);

    private ClientSpider clientSpider;
    private String url;
    private int timeout;
    private WebDriver wd;

    public ClientSpiderTask(ClientSpider clientSpider, String url, int timeout) {
        this.clientSpider = clientSpider;
        this.url = url;
        this.timeout = timeout;
    }

    @Override
    public void run() {
        if (clientSpider.isStopped()) {
            return;
        }
        while (clientSpider.isPaused()) {
            try {
                Thread.sleep(200);
            } catch (InterruptedException e) {
                // Ignore
            }
        }
        boolean ok = false;
        long startTime = System.currentTimeMillis();
        try {
            wd = this.clientSpider.getWebDriver();
            startTime = System.currentTimeMillis();
            wd.manage().timeouts().pageLoadTimeout(Duration.ofSeconds(this.timeout));
            wd.get(url);
            String actualUrl = wd.getCurrentUrl();
            if (!url.equals(actualUrl)) {
                clientSpider.setRedirect(url, actualUrl);
            }
            ok = true;
        } catch (Exception e) {
            LOGGER.warn("Task failed {} {}", url, e.getMessage(), e);
        }
        if (wd != null) {
            this.clientSpider.returnWebDriver(wd);
        }
        LOGGER.debug(
                "Task completed {} {} in {} secs",
                url,
                ok,
                (System.currentTimeMillis() - startTime) / 1000);
        this.clientSpider.postTaskExecution(this);
    }
}
