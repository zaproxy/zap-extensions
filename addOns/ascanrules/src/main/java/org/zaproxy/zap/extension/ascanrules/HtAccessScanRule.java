/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2018 The ZAP Development Team
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
package org.zaproxy.zap.extension.ascanrules;

import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import net.htmlparser.jericho.HTMLElementName;
import net.htmlparser.jericho.Source;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.commonlib.AbstractAppFilePlugin;
import org.zaproxy.addon.commonlib.CommonAlertTag;
import org.zaproxy.addon.commonlib.PolicyTag;
import org.zaproxy.zap.model.Tech;
import org.zaproxy.zap.model.TechSet;

public class HtAccessScanRule extends AbstractAppFilePlugin implements CommonActiveScanRuleInfo {

    private static final String MESSAGE_PREFIX = "ascanrules.htaccess.";
    private static final int PLUGIN_ID = 40032;

    private static final Map<String, String> ALERT_TAGS;

    static {
        Map<String, String> alertTags =
                new HashMap<>(
                        CommonAlertTag.toMap(
                                CommonAlertTag.OWASP_2021_A05_SEC_MISCONFIG,
                                CommonAlertTag.OWASP_2017_A06_SEC_MISCONFIG,
                                CommonAlertTag.WSTG_V42_CONF_05_ENUMERATE_INFRASTRUCTURE));
        alertTags.put(PolicyTag.QA_FULL.getTag(), "");
        ALERT_TAGS = Collections.unmodifiableMap(alertTags);
    }

    private static final int TEN_K = 10 * 1024;

    private static final List<String> COMMON_DIRECTIVES =
            List.of(
                    "addtype",
                    "allow",
                    "deny",
                    "errordocument",
                    "files",
                    "limit",
                    "options",
                    "order",
                    "redirect",
                    "require",
                    "rewritecond",
                    "rewriterule");

    public HtAccessScanRule() {
        super(".htaccess", MESSAGE_PREFIX);
    }

    @Override
    public int getId() {
        return PLUGIN_ID;
    }

    @Override
    public boolean targets(TechSet technologies) {
        return technologies.includes(Tech.Apache);
    }

    @Override
    public boolean isFalsePositive(HttpMessage msg) {
        if (msg.getResponseBody().length() == 0) {
            // No content
            return true;
        }
        if (!msg.getResponseHeader().isText()) {
            // Pretty unlikely to be an htaccess file
            return true;
        }
        if (msg.getResponseHeader().isXml()) {
            // Pretty unlikely to be an htaccess file
            return true;
        }
        if (msg.getResponseHeader().isJson()) {
            // Pretty unlikely to be an htaccess file
            return true;
        }
        // Check for HTML content, no matter what content type
        try {
            Source src = new Source(msg.getResponseBody().toString());
            if (src.getFirstElement(HTMLElementName.HTML) != null) {
                // It looks like HTML
                return true;
            }
        } catch (Exception e) {
            // Ignore exceptions - they indicate its probably not really HTML
        }
        // Check for common htaccess directives in the first 10k
        String body = msg.getResponseBody().toString();
        if (body.length() > TEN_K) {
            body = body.substring(0, TEN_K);
        }
        String body10k = body.toLowerCase(Locale.ROOT);
        if (!COMMON_DIRECTIVES.stream().anyMatch(d -> body10k.contains(d))) {
            // No common directives present
            return true;
        }
        // Final check - make sure there is at least one directive in the right location
        for (String line : body10k.split("\n")) {
            String lineTrim = line.strip();
            if (COMMON_DIRECTIVES.stream()
                    .anyMatch(
                            d ->
                                    lineTrim.startsWith(d)
                                            && lineTrim.length() > d.length()
                                            && Character.isWhitespace(
                                                    lineTrim.charAt(d.length())))) {
                // Found a common directive at the start of a line with whitespace after it.
                return false;
            }
        }
        return true;
    }

    @Override
    public Map<String, String> getAlertTags() {
        return ALERT_TAGS;
    }

    @Override
    public int getCweId() {
        return 94; // Configuration
    }

    @Override
    public int getWascId() {
        return 14; // Server Misconfiguration
    }
}
