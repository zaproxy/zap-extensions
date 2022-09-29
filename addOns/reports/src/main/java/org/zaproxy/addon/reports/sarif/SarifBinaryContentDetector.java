/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2021 The ZAP Development Team
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
package org.zaproxy.addon.reports.sarif;

import static java.util.Objects.requireNonNull;

import org.parosproxy.paros.network.HttpHeader;

public class SarifBinaryContentDetector {

    public static final SarifBinaryContentDetector DEFAULT = new SarifBinaryContentDetector();

    /**
     * Detect binary content by inspecting the given HTTP header and the returned normalized
     * (lowercased) content type. see <a
     * href="https://www.iana.org/assignments/media-types/media-types.xhtml">IANA Mime type list</a>
     * for a list of mime types.
     *
     * @param header the HTTP header to inspect
     * @return <code>true</code> when binary content otherwise <code>false</code>
     */
    public boolean isBinaryContent(HttpHeader header) {
        requireNonNull(header, "Header parameter may not be null!");

        String contentType = header.getNormalisedContentTypeValue();
        if (contentType == null) {
            // if not set, we assume it is binary
            return true;
        }
        return !isTextBasedContentType(contentType);
    }

    private boolean isTextBasedContentType(String contentType) {
        return isPlainText(contentType)
                || isJSON(contentType)
                || isXML(contentType)
                || isJavaScript(contentType);
    }

    private boolean isXML(String contentType) {
        return contentType.contains("/xml");
    }

    private boolean isJSON(String contentType) {
        return contentType.contains("/json");
    }

    private boolean isPlainText(String contentType) {
        return contentType.startsWith("text");
    }

    private boolean isJavaScript(String contentType) {
        return contentType.contains("javascript") || contentType.contains("ecmascript");
    }
}
