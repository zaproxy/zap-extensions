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
import org.apache.commons.lang3.StringUtils;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpMessage;

public final class MessageValidator {

    public enum Result {
        INVALID,
        VALID_SCHEMA,
        VALID_ENDPOINT
    }

    private MessageValidator() {}

    public static Result validate(HttpMessage message) {
        String uri = message.getRequestHeader().getURI().toString();
        if (message.getResponseHeader().getHeader(HttpHeader.CONTENT_TYPE) == null) {
            return Result.INVALID;
        }
        if (uri.endsWith(".graphql") || uri.endsWith(".graphqls")) {
            return Result.VALID_SCHEMA;
        }
        if (isGraphQlEndpointResponse(
                message.getResponseBody().toString(),
                message.getResponseHeader().getHeader(HttpHeader.CONTENT_TYPE))) {
            return Result.VALID_ENDPOINT;
        }
        return Result.INVALID;
    }

    static boolean isGraphQlEndpointResponse(String responseBody, String contentType) {
        // The GraphQL Spec does not mandate the usage of JSON, but most popular implementations
        // only support JSON as the response format. So, it may be reasonable to assume that if
        // the response body is not JSON, then it is not from a GraphQL endpoint.
        if (contentType == null) {
            return false;
        }
        if (contentType.toLowerCase(Locale.ROOT).startsWith("application/json")) {
            String responseBodyStart =
                    StringUtils.left(responseBody, 50)
                            .toLowerCase(Locale.ROOT)
                            .replaceAll("\\s+", "");
            // Ref: https://spec.graphql.org/October2021/#sec-Response-Format
            return responseBodyStart.startsWith("{\"errors\":")
                    || responseBodyStart.startsWith("{\"data\":")
                    || responseBodyStart.startsWith("{\"extensions\":");
        }
        return false;
    }
}
