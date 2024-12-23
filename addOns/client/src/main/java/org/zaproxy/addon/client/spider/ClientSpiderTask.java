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
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.openqa.selenium.WebDriver;

public class ClientSpiderTask implements Runnable {

    private static final Logger LOGGER = LogManager.getLogger(ClientSpiderTask.class);

    private final int id;
    private ClientSpider clientSpider;
    private List<SpiderAction> actions;
    private int timeout;
    private WebDriver wd;

    public ClientSpiderTask(
            int id, ClientSpider clientSpider, List<SpiderAction> actions, int timeout) {
        this.id = id;
        this.clientSpider = clientSpider;
        this.actions = actions;
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
            actions.forEach(e -> e.run(wd));
            ok = true;
        } catch (Exception e) {
            LOGGER.warn("Task {} failed {}", id, e.getMessage(), e);
        }
        if (wd != null) {
            this.clientSpider.returnWebDriver(wd);
        }
        LOGGER.debug(
                "Task {} completed {} in {} secs",
                id,
                ok,
                (System.currentTimeMillis() - startTime) / 1000);
        this.clientSpider.postTaskExecution(this);
    }
}
