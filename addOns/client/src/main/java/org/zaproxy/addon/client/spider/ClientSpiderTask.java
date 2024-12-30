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
import java.util.Locale;
import lombok.Getter;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.openqa.selenium.WebDriver;
import org.parosproxy.paros.Constant;
import org.zaproxy.addon.client.spider.ClientSpider.WebDriverProcess;

public class ClientSpiderTask implements Runnable {

    public enum Status {
        QUEUED,
        STOPPED,
        PAUSED,
        RUNNING,
        FINISHED,
        FAILED;

        @Override
        public String toString() {
            return Constant.messages.getString(
                    "client.spider.task.stats." + this.name().toLowerCase(Locale.ROOT));
        }
    }

    private static final Logger LOGGER = LogManager.getLogger(ClientSpiderTask.class);

    @Getter private final int id;
    @Getter private String displayName;
    @Getter private String detailsString;
    private ClientSpider clientSpider;
    private List<SpiderAction> actions;
    private int timeout;
    @Getter private Status status;
    @Getter private String error;

    public ClientSpiderTask(
            int id,
            ClientSpider clientSpider,
            List<SpiderAction> actions,
            int timeout,
            String displayName,
            String detailsString) {
        this.id = id;
        this.displayName = displayName;
        this.detailsString = detailsString;
        this.clientSpider = clientSpider;
        this.actions = actions;
        this.timeout = timeout;
        this.status = Status.QUEUED;
    }

    @Override
    public void run() {
        if (clientSpider.isStopped()) {
            this.status = Status.STOPPED;
            this.clientSpider.taskStateChange(this);
            return;
        }
        while (clientSpider.isPaused()) {
            this.status = Status.PAUSED;
            this.clientSpider.taskStateChange(this);
            try {
                Thread.sleep(200);
            } catch (InterruptedException e) {
                // Ignore
            }
        }
        boolean ok = false;
        long startTime = System.currentTimeMillis();
        this.status = Status.RUNNING;
        this.clientSpider.taskStateChange(this);
        WebDriverProcess wdp = null;
        try {
            wdp = this.clientSpider.getWebDriverProcess();
            WebDriver wd = wdp.getWebDriver();
            startTime = System.currentTimeMillis();
            wd.manage().timeouts().pageLoadTimeout(Duration.ofSeconds(this.timeout));
            actions.forEach(e -> e.run(wd));
            ok = true;
            this.status = Status.FINISHED;
            this.clientSpider.taskStateChange(this);
        } catch (Exception e) {
            LOGGER.warn("Task {} failed {}", id, e.getMessage(), e);
            this.status = Status.FAILED;
            this.error = e.getMessage();
            this.clientSpider.taskStateChange(this);
        }
        if (wdp != null) {
            this.clientSpider.returnWebDriverProcess(wdp);
        }
        LOGGER.debug(
                "Task {} completed {} in {} secs",
                id,
                ok,
                (System.currentTimeMillis() - startTime) / 1000);
        this.clientSpider.postTaskExecution(this);
    }
}
