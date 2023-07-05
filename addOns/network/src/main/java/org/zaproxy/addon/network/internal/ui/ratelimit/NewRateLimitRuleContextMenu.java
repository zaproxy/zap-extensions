/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2022 The ZAP Development Team
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
package org.zaproxy.addon.network.internal.ui.ratelimit;

import org.apache.commons.httpclient.URIException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.network.internal.ratelimit.RateLimitOptions;
import org.zaproxy.addon.network.internal.ratelimit.RateLimitRule;
import org.zaproxy.zap.view.messagecontainer.http.HttpMessageContainer;
import org.zaproxy.zap.view.popup.PopupMenuItemHttpMessageContainer;

/**
 * Base context menu item to add rate limit rule.
 *
 * @see HttpMessageContainer
 */
@SuppressWarnings("serial")
public abstract class NewRateLimitRuleContextMenu extends PopupMenuItemHttpMessageContainer {

    private static final Logger LOGGER = LogManager.getLogger(NewRateLimitRuleContextMenu.class);

    private final RateLimitOptions rateLimitOptions;

    protected NewRateLimitRuleContextMenu(String label, RateLimitOptions rateLimitOptions) {
        super(label);
        this.rateLimitOptions = rateLimitOptions;
    }

    @Override
    public void performAction(HttpMessage msg) {
        RateLimitRule rule;
        try {
            rule = createRule(msg);
        } catch (Exception e) {
            LOGGER.warn("Failed to create the rule:", e);
            return;
        }

        rateLimitOptions.addRule(rule);
        Control.getSingleton().getMenuToolsControl().options(RateLimitOptionsPanel.PANEL_NAME);
    }

    /** Creates a rule based on the selected message. */
    protected abstract RateLimitRule createRule(HttpMessage msg) throws URIException;

    @Override
    public boolean isSafe() {
        return true;
    }
}
