/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2023 The ZAP Development Team
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
package org.zaproxy.addon.authhelper;

import java.util.List;
import org.apache.commons.httpclient.URI;
import org.parosproxy.paros.network.HtmlParameter;
import org.zaproxy.zap.extension.anticsrf.AntiCsrfToken;

public class AuthenticationRequestDetails {

    public enum AuthDataType {
        FORM,
        JSON
    };

    private final URI uri;
    private final HtmlParameter userParam;
    private final HtmlParameter passwordParam;
    private final String referer;
    private final List<AntiCsrfToken> tokens;
    private final AuthDataType type;
    private final int confidence;

    public AuthenticationRequestDetails(
            URI uri,
            HtmlParameter userParam,
            HtmlParameter passwordParam,
            AuthDataType type,
            String referer,
            List<AntiCsrfToken> tokens,
            int confidence) {
        super();
        this.uri = uri;
        this.userParam = userParam;
        this.type = type;
        this.passwordParam = passwordParam;
        this.referer = referer;
        this.tokens = tokens;
        this.confidence = confidence;
    }

    public URI getUri() {
        return uri;
    }

    public HtmlParameter getUserParam() {
        return userParam;
    }

    public HtmlParameter getPasswordParam() {
        return passwordParam;
    }

    public AuthDataType getType() {
        return type;
    }

    public String getReferer() {
        return referer;
    }

    public List<AntiCsrfToken> getTokens() {
        return tokens;
    }

    public int getConfidence() {
        return confidence;
    }
}
