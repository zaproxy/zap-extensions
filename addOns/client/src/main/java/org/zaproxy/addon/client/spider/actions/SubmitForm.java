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

import java.util.Map;
import java.util.Objects;
import org.apache.commons.httpclient.URI;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.openqa.selenium.By;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.WebElement;
import org.zaproxy.addon.commonlib.ValueProvider;
import org.zaproxy.zap.utils.Stats;

public class SubmitForm extends BaseElementAction {

    private static final Logger LOGGER = LogManager.getLogger(SubmitForm.class);

    private static final String STATS_PREFIX = "stats.client.spider.action.form";

    private final String tagName;
    private final int formIndex;

    public SubmitForm(ValueProvider valueProvider, URI uri, Map<String, String> elementData) {
        super(valueProvider, uri);
        Objects.requireNonNull(elementData);
        tagName = getTagName(elementData);
        formIndex = Integer.valueOf(elementData.get("formId"));
    }

    @Override
    public void run(WebDriver wd, WebElement form, String statsPrefix) {
        String action = form.getDomAttribute("action");
        fillInputs(form.findElements(By.xpath("//input")), action, statsPrefix);

        try {
            form.submit();
            Stats.incCounter(statsPrefix + ".submitted");
        } catch (Exception e) {
            Stats.incCounter(statsPrefix + ".exception");
            LOGGER.debug("An error occurred while submitting the form:", e);
        }
    }

    @Override
    protected By getElementBy() {
        return By.xpath("(//" + tagName + ")[" + (formIndex + 1) + "]");
    }

    @Override
    protected String getStatsPrefix() {
        return STATS_PREFIX + "." + formIndex;
    }

    public static boolean isSupported(Map<String, String> data) {
        return data.containsKey("formId") && "FORM".equalsIgnoreCase(getTagName(data));
    }
}
