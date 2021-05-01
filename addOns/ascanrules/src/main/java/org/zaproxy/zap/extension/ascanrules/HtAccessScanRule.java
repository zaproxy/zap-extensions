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

import net.htmlparser.jericho.HTMLElementName;
import net.htmlparser.jericho.Source;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.commonlib.AbstractAppFilePlugin;
import org.zaproxy.zap.model.Tech;
import org.zaproxy.zap.model.TechSet;

public class HtAccessScanRule extends AbstractAppFilePlugin {

    private static final String MESSAGE_PREFIX = "ascanrules.htaccess.";
    private static final int PLUGIN_ID = 40032;

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
        if (msg.getResponseHeader().isXml()) {
            // Pretty unlikely to be an htaccess file
            return true;
        }
        if (msg.getResponseHeader().isJson()) {
            // Pretty unlikely to be an htaccess file
            return true;
        }
        if (msg.getResponseHeader().isHtml()) {
            // Double check it does really look like HTML
            try {
                Source src = new Source(msg.getResponseBody().toString());
                if (src.getFirstElement(HTMLElementName.HTML) != null) {
                    // Yep, it really looks like HTML
                    return true;
                }
            } catch (Exception e) {
                // Ignore exceptions - they indicate its probably not really HTML
            }
        }

        return false;
    }
}
