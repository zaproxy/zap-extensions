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
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.WebElement;
import org.zaproxy.addon.client.spider.SpiderAction;
import org.zaproxy.addon.commonlib.ValueProvider;
import org.zaproxy.zap.utils.Stats;

abstract class BaseElementAction implements SpiderAction {

    private static final Logger LOGGER = LogManager.getLogger(BaseElementAction.class);

    private final ValueProvider valueProvider;
    private final URI uri;

    protected BaseElementAction(ValueProvider valueProvider, URI uri) {
        this.valueProvider = Objects.requireNonNull(valueProvider);
        this.uri = Objects.requireNonNull(uri);
    }

    protected URI getUri() {
        return uri;
    }

    @Override
    public final void run(WebDriver wd) {
        String statsPrefix = getStatsPrefix();
        Stats.incCounter(statsPrefix);

        By by = getElementBy();
        if (by == null) {
            Stats.incCounter(statsPrefix + ".noby");
            return;
        }

        WebElement element;
        try {
            element = wd.findElement(by);
        } catch (Exception e) {
            Stats.incCounter(statsPrefix + ".notfound");
            return;
        }

        if (!element.isDisplayed()) {
            Stats.incCounter(statsPrefix + ".notdisplayed");
            return;
        }

        run(wd, element, statsPrefix);
    }

    protected abstract String getStatsPrefix();

    protected abstract By getElementBy();

    protected abstract void run(WebDriver wd, WebElement element, String statsPrefix);

    protected void fillInputs(List<WebElement> inputs, String action, String statsPrefix) {
        inputs.forEach(input -> fillInput(input, action, statsPrefix));
    }

    protected void fillInput(WebElement input, String action, String statsPrefix) {
        if (!input.isDisplayed()) {
            Stats.incCounter(statsPrefix + ".input.notdisplayed");
            return;
        }

        String type = getAttribute(input, "type");
        if (type == null) {
            Stats.incCounter(statsPrefix + ".input.notype");
            return;
        }

        String value =
                valueProvider.getValue(
                        uri,
                        action,
                        getAttribute(input, "name"),
                        getAttribute(input, "value"),
                        List.of(),
                        Map.of(),
                        Map.of("Control Type", getControlType(type), "type", type));

        try {
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

    protected static String getTagName(Map<String, String> data) {
        return data.get("tagName");
    }
}
