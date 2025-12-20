/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2025 The ZAP Development Team
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
package org.zaproxy.addon.network.internal;

import java.nio.charset.StandardCharsets;
import org.apache.commons.lang3.StringUtils;
import org.parosproxy.paros.network.HttpBody;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpMessage.CharsetProvider;

public class DefaultCharsetProvider implements CharsetProvider {

    @Override
    public String get(HttpHeader header, HttpBody body) {
        String charset = header.getCharset();
        if (!StringUtils.isBlank(charset)) {
            return charset;
        }

        if (header.hasContentType(HttpHeader.JSON_CONTENT_TYPE)) {
            return StandardCharsets.UTF_8.name();
        }
        return null;
    }
}
