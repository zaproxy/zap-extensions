/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2019 The ZAP Development Team
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
package org.zaproxy.addon.commonlib.http.domains;

import org.apache.commons.httpclient.URI;
import org.apache.commons.httpclient.URIException;

public class SameOriginPolicyTrust implements Trust {
    private final URI origin;

    public SameOriginPolicyTrust(URI origin) {
        this.origin = origin;
    }

    @Override
    public boolean isTrusted(String url) {
        try {
            URI resourceUri = new URI(url, false);
            return origin.getScheme().equals(resourceUri.getScheme())
                    && origin.getAuthority().equals(resourceUri.getAuthority())
                    && origin.getPort() == resourceUri.getPort();
        } catch (URIException e) {
            // Badly formatted resource should be ignored
            return true;
        }
    }
}
