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

import org.apache.commons.httpclient.URI;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.openqa.selenium.WebElement;
import org.zaproxy.addon.client.internal.ClientSideComponent;
import org.zaproxy.addon.client.spider.TaskContext;
import org.zaproxy.zap.utils.Stats;

public class SubmitForm extends BaseElementAction {

    private static final Logger LOGGER = LogManager.getLogger(SubmitForm.class);

    private static final String STATS_PREFIX = "stats.client.spider.action.form";

    private final int formIndex;

    public SubmitForm(URI uri, ClientSideComponent component) {
        super(uri, component);
        this.formIndex = component.getFormId();
    }

    @Override
    public boolean run(TaskContext context, WebElement form, String statsPrefix) {
        String action = form.getDomAttribute("action");
        fillComponents(context, action, statsPrefix);

        try {
            form.submit();
            Stats.incCounter(statsPrefix + ".submitted");
            return true;
        } catch (Exception e) {
            Stats.incCounter(statsPrefix + ".exception");
            LOGGER.debug("An error occurred while submitting the form:", e);
        }
        return false;
    }

    @Override
    protected String getStatsPrefix() {
        return STATS_PREFIX + "." + formIndex;
    }

    public static boolean isSupported(ClientSideComponent component) {
        return "FORM".equalsIgnoreCase(component.getTagName());
    }
}
