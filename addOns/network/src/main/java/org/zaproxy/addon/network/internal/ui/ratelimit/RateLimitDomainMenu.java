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

import java.util.LinkedList;
import java.util.List;
import org.apache.commons.httpclient.URIException;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.network.internal.ratelimit.RateLimitOptions;
import org.zaproxy.addon.network.internal.ratelimit.RateLimitRule;
import org.zaproxy.zap.view.messagecontainer.http.HttpMessageContainer;

/**
 * Context menu item to limit rate for the domain.
 *
 * @see HttpMessageContainer
 */
public class RateLimitDomainMenu extends NewRateLimitRuleContextMenu {

    private static final long serialVersionUID = 1L;

    public RateLimitDomainMenu(RateLimitOptions rateLimitOptions, String label) {
        super(label, rateLimitOptions);
    }

    @Override
    protected RateLimitRule createRule(HttpMessage msg) throws URIException {
        String host = msg.getRequestHeader().getURI().getHost();
        String domain;
        if (RateLimitRule.isIpAddress(host)) {
            domain = host;
        } else {
            LinkedList<String> hostParts = new LinkedList<>(List.of(host.split("[.]")));
            if (hostParts.size() >= 2) {
                LinkedList<String> domainParts = new LinkedList<>();
                if (hostParts.peekLast().length() == 2) {
                    // country code
                    domainParts.push(hostParts.removeLast());
                    if (hostParts.peekLast().length() >= 2 && hostParts.peekLast().length() <= 3) {
                        domainParts.push(hostParts.removeLast()); // TLD
                    }
                } else {
                    domainParts.push(hostParts.removeLast()); // TLD
                }

                if (!hostParts.isEmpty()) {
                    domainParts.push(hostParts.removeLast()); // SLD
                }

                domain = String.join(".", domainParts);
            } else {
                domain = host;
            }
        }
        return new RateLimitRule(domain, domain, false, 1, RateLimitRule.GroupBy.RULE, true);
    }
}
