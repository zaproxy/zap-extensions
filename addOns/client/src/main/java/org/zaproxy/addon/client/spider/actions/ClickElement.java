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

import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.function.Predicate;
import net.sf.json.JSONObject;
import org.apache.commons.httpclient.URI;
import org.apache.commons.lang3.StringUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.openqa.selenium.By;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.WebElement;
import org.zaproxy.addon.commonlib.ValueProvider;
import org.zaproxy.zap.utils.Stats;

public class ClickElement extends BaseElementAction {

    private static final Logger LOGGER = LogManager.getLogger(ClickElement.class);

    private static final String STATS_PREFIX = "stats.client.spider.action.click";

    private static final List<String> INTERACTIVE_ARIA_ROLES =
            Arrays.asList(
                    "button",
                    "link",
                    "checkbox",
                    "radio",
                    "switch",
                    "tab",
                    "menuitem",
                    "menuitemcheckbox",
                    "menuitemradio",
                    "option",
                    "treeitem",
                    "combobox",
                    "listbox",
                    "slider",
                    "spinbutton",
                    "searchbox",
                    "textbox");

    private final Map<String, String> elementData;
    private final String tagName;

    public ClickElement(ValueProvider valueProvider, URI uri, Map<String, String> elementData) {
        super(valueProvider, uri);

        this.elementData = Objects.requireNonNull(elementData);
        tagName = getTagName(elementData);
    }

    @Override
    public void run(WebDriver wd, WebElement element, String statsPrefix) {
        fillInputs(wd.findElements(By.xpath("//input")), getUri().toString(), statsPrefix);

        try {
            element.click();
            Stats.incCounter(statsPrefix + ".clicked");
        } catch (Exception e) {
            Stats.incCounter(statsPrefix + ".exception");
            LOGGER.debug("An error occurred while clicking the element:", e);
        }
    }

    @Override
    protected By getElementBy() {
        return getBy(elementData);
    }

    @Override
    protected String getStatsPrefix() {
        return STATS_PREFIX + ".tag." + tagName;
    }

    private static By getBy(Map<String, String> data) {
        String id = data.get("id");
        if (StringUtils.isNotBlank(id)) {
            return By.id(id);
        }

        String ariaString = data.get("ariaIdentification");
        if (StringUtils.isNotBlank(ariaString)) {
            Map<String, String> ariaAttrs = parseAriaIdentification(ariaString);

            if (!ariaAttrs.isEmpty()) {
                StringBuilder xpathBuilder = new StringBuilder("//*");
                for (Map.Entry<String, String> entry : ariaAttrs.entrySet()) {
                    xpathBuilder
                            .append("[@")
                            .append(entry.getKey())
                            .append("='")
                            .append(entry.getValue())
                            .append("']");
                }
                return By.xpath(xpathBuilder.toString());
            }
        }

        String tag = getTagName(data);
        String text = data.get("text");
        if ("INPUT".equalsIgnoreCase(tag)) {
            return By.xpath("//" + tag + "[@value='" + text + "']");
        }

        if (StringUtils.isNotBlank(text)) {
            return By.xpath("//" + tag + "[contains(text(), '" + text + "')]");
        }

        return By.tagName(tag);
    }

    public static boolean isSupported(Predicate<String> scopeChecker, Map<String, String> data) {
        String tag = getTagName(data);
        if (tag == null) {
            return false;
        }

        String href = data.get("href");
        if (href != null && !scopeChecker.test(href)) {
            return false;
        }

        switch (tag) {
            case "A", "BUTTON":
                return true;

            case "INPUT":
                String type = data.get("tagType");
                return "submit".equalsIgnoreCase(type) || "button".equalsIgnoreCase(type);

            default:
                String role = data.get("role");
                return StringUtils.isNotBlank(role) && INTERACTIVE_ARIA_ROLES.contains(role.toLowerCase());
        }
    }

    private static Map<String, String> parseAriaIdentification(String ariaString) {
        Map<String, String> result = new HashMap<>();
        if (ariaString == null || ariaString.isEmpty()) {
            return result;
        }
        try {
            JSONObject json = JSONObject.fromObject(ariaString);
            for (Object key : json.keySet()) {
                result.put(key.toString(), json.getString(key.toString()));
            }
        } catch (Exception e) {
            LOGGER.debug("Failed to parse ariaIdentification: {}", ariaString, e);
        }
        return result;
    }
}
