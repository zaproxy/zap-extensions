/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2020 The ZAP Development Team
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
package org.zaproxy.addon.graphql;

import java.util.Locale;
import org.apache.commons.lang.StringUtils;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpMessage;

public final class MessageValidator {

    protected enum Result {
        INVALID,
        VALID_SCHEMA,
        VALID_ENDPOINT
    };

    private MessageValidator() {}

    protected static Result validate(HttpMessage message) {
        String uri = message.getRequestHeader().getURI().toString();
        String contentType =
                message.getResponseHeader()
                        .getHeader(HttpHeader.CONTENT_TYPE)
                        .toLowerCase(Locale.ROOT);

        if (uri.endsWith(".graphql")
                || uri.endsWith(".graphqls")
                || contentType.startsWith("application/graphql")) {
            return Result.VALID_SCHEMA;
        }

        String responseBodyStart =
                StringUtils.left(message.getResponseBody().toString(), 250)
                        .toLowerCase(Locale.ROOT);
        if (responseBodyStart.contains("__schema") || responseBodyStart.contains("graphql")) {
            return Result.VALID_ENDPOINT;
        }

        return Result.INVALID;
    }
}
