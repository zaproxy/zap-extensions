/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2024 The ZAP Development Team
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
package org.zaproxy.addon.client.spider.actions;

import java.util.List;
import java.util.Map;
import java.util.Objects;
import org.apache.commons.httpclient.URI;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.openqa.selenium.By;
import org.openqa.selenium.WebElement;
import org.zaproxy.addon.client.internal.ClientSideComponent;
import org.zaproxy.addon.client.spider.SpiderAction;
import org.zaproxy.addon.client.spider.TaskContext;
import org.zaproxy.zap.utils.Stats;

abstract class BaseElementAction implements SpiderAction {

    private static final Logger LOGGER = LogManager.getLogger(BaseElementAction.class);

    private final URI uri;
    protected final ClientSideComponent component;

    protected BaseElementAction(URI uri, ClientSideComponent component) {
        this.uri = Objects.requireNonNull(uri);
        this.component = Objects.requireNonNull(component);
    }

    protected URI getUri() {
        return uri;
    }

    @Override
    public final boolean run(TaskContext context) {
        String statsPrefix = getStatsPrefix();
        Stats.incCounter(statsPrefix);

        By by = component.getBy();
        if (by == null) {
            Stats.incCounter(statsPrefix + ".noby");
            return false;
        }

        WebElement element;
        try {
            element = context.getWebDriver().findElement(by);
        } catch (Exception e) {
            Stats.incCounter(statsPrefix + ".notfound");
            return false;
        }

        if (!element.isDisplayed()) {
            Stats.incCounter(statsPrefix + ".notdisplayed");
            return false;
        }

        String urlBeforeAction = context.getWebDriver().getCurrentUrl();
        if (!run(context, element, statsPrefix) || !context.getWaitStrategy().waitAfterAction()) {
            return false;
        }

        if (context.isStopped()) {
            return false;
        }

        String currentUrl = context.getWebDriver().getCurrentUrl();
        if (!urlBeforeAction.equals(currentUrl)) {
            return !context.isStopped() && context.getWaitStrategy().waitAfterPageLoad(currentUrl);
        }

        return true;
    }

    protected abstract String getStatsPrefix();

    protected abstract boolean run(TaskContext context, WebElement element, String statsPrefix);

    protected void fillComponents(TaskContext context, String action, String statsPrefix) {
        context.getWebDriver()
                .findElements(By.xpath("//input | //textarea"))
                .forEach(input -> fillInput(context, input, action, statsPrefix));
    }

    protected void fillInput(
            TaskContext context, WebElement input, String action, String statsPrefix) {
        if (!input.isDisplayed()) {
            Stats.incCounter(statsPrefix + ".input.notdisplayed");
            return;
        }

        String type;
        String controlType;
        if ("textarea".equalsIgnoreCase(input.getTagName())) {
            type = "textarea";
            controlType = "text";
        } else {
            type = getAttribute(input, "type");
            if (type == null) {
                Stats.incCounter(statsPrefix + ".input.notype");
                return;
            }
            controlType = getControlType(type);
        }

        String value =
                context.getValueProvider()
                        .getValue(
                                uri,
                                action,
                                getAttribute(input, "name"),
                                getAttribute(input, "value"),
                                List.of(),
                                Map.of(),
                                Map.of("Control Type", controlType, "type", type));

        try {
            input.clear();
            input.sendKeys(value);
            Stats.incCounter(statsPrefix + ".input." + type + ".sendkeys");
        } catch (Exception e) {
            Stats.incCounter(statsPrefix + ".input." + type + ".exception");
            LOGGER.debug("An error occurred while filling form input:", e);
        }
    }

    private static String getAttribute(WebElement element, String name) {
        String value = element.getDomAttribute(name);
        if (value != null) {
            return value;
        }
        return element.getDomProperty(name);
    }

    private static String getControlType(String type) {
        return !"password".equalsIgnoreCase(type) && !"file".equalsIgnoreCase(type) ? "text" : type;
    }
}
