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
package org.zaproxy.zap.extension.ascanrulesBeta;

import java.util.Map;
import java.util.regex.Pattern;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.commonlib.AbstractAppFilePlugin;
import org.zaproxy.addon.commonlib.CommonAlertTag;

public class EnvFileScanRule extends AbstractAppFilePlugin {

    private static final String MESSAGE_PREFIX = "ascanbeta.envfiles.";

    private static final int PLUGIN_ID = 40034;
    private static final int RESPONSE_LEN_MAX = 500;

    private static final Pattern COMMENT_PATTERN =
            Pattern.compile("^#\\s{0,10}\\w+", Pattern.MULTILINE);
    private static final Pattern KEYVAL_PATTERN = Pattern.compile("^\\w+=\\w+", Pattern.MULTILINE);
    private static final Map<String, String> ALERT_TAGS =
            CommonAlertTag.toMap(
                    CommonAlertTag.OWASP_2021_A05_SEC_MISCONFIG,
                    CommonAlertTag.OWASP_2017_A06_SEC_MISCONFIG,
                    CommonAlertTag.WSTG_V42_CONF_05_ENUMERATE_INFRASTRUCTURE);

    public EnvFileScanRule() {
        super(".env", MESSAGE_PREFIX);
    }

    @Override
    public int getId() {
        return PLUGIN_ID;
    }

    @Override
    public Map<String, String> getAlertTags() {
        return ALERT_TAGS;
    }

    // Environment files come in many flavors but mostly they are KEY=VALUE formatted Here's the
    // trick, NGINX returns them as binary/octet-stream content-type Apache just returns the text
    // with no content-type Just looking for content returned with status code 200 and '#' and '='
    // is a FP nightmare Because that's basically ALL html files

    @Override
    public boolean isFalsePositive(HttpMessage msg) {
        String responseBody = msg.getResponseBody().toString();

        if (responseBody.length() > RESPONSE_LEN_MAX) {
            return true;
        }

        String contentType = msg.getResponseHeader().getNormalisedContentTypeValue();
        if (contentType == null || contentType.equals("application/octet-stream")) {
            boolean hasComments = COMMENT_PATTERN.matcher(responseBody).find();
            boolean hasKeyvalue = KEYVAL_PATTERN.matcher(responseBody).find();
            return !hasComments && !hasKeyvalue;
        }
        return true;
    }
}
