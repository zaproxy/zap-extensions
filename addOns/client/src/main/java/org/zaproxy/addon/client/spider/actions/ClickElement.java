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

import java.util.function.Predicate;
import org.apache.commons.httpclient.URI;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.openqa.selenium.By;
import org.openqa.selenium.WebElement;
import org.openqa.selenium.support.ui.ExpectedCondition;
import org.openqa.selenium.support.ui.ExpectedConditions;
import org.zaproxy.addon.client.internal.ClientSideComponent;
import org.zaproxy.addon.client.internal.InteractableState;
import org.zaproxy.addon.client.spider.TaskContext;
import org.zaproxy.zap.utils.Stats;

public class ClickElement extends BaseElementAction {

    private static final Logger LOGGER = LogManager.getLogger(ClickElement.class);

    private static final String STATS_PREFIX = "stats.client.spider.action.click";

    private final boolean passive;

    public ClickElement(URI uri, ClientSideComponent component, boolean passive) {
        super(uri, component);

        this.passive = passive;
    }

    @Override
    public boolean run(TaskContext context, WebElement element, String statsPrefix) {
        if (!passive) {
            fillComponents(context, getUri().toString(), statsPrefix);
        }

        try {
            if (!passive) {
                context.setLastActionedComponent(component);
            }
            element.click();
            Stats.incCounter(statsPrefix + ".clicked");
            return true;
        } catch (Exception e) {
            Stats.incCounter(statsPrefix + ".exception");
            LOGGER.debug("An error occurred while clicking the element:", e);
        }
        return false;
    }

    @Override
    protected ExpectedCondition<WebElement> getExpectedCondition(By by) {
        return ExpectedConditions.elementToBeClickable(by);
    }

    @Override
    protected String getStatsPrefix() {
        return STATS_PREFIX + ".tag." + component.getTagName();
    }

    public static boolean isSupported(
            Predicate<String> scopeChecker, ClientSideComponent component) {
        String tag = component.getTagName();
        if (tag == null) {
            return false;
        }

        String href = component.getHref();
        if (href != null && !scopeChecker.test(href)) {
            return false;
        }

        switch (tag) {
            case "A", "BUTTON":
                return true;

            case "INPUT":
                String type = component.getTagType();
                return "submit".equalsIgnoreCase(type) || "button".equalsIgnoreCase(type);

            default:
                InteractableState interactable = component.getInteractable();
                return interactable != null && interactable.isPointer();
        }
    }
}
