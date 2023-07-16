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
package org.zaproxy.zap.extension.openapi;

import java.util.Objects;
import org.parosproxy.paros.Constant;

public final class OpenApiExceptions {

    private OpenApiExceptions() {}

    public static class EmptyDefinitionException extends RuntimeException {
        static final long serialVersionUID = 1;

        public EmptyDefinitionException() {
            super(Constant.messages.getString("openapi.import.error.emptyDefn"));
        }
    }

    public static class InvalidDefinitionException extends RuntimeException {
        static final long serialVersionUID = 1;

        public InvalidDefinitionException() {
            super(Constant.messages.getString("openapi.import.error.invalidDefn"));
        }
    }

    /** Indicates that a URL is invalid. */
    public static class InvalidUrlException extends RuntimeException {

        public static final long serialVersionUID = 1;

        private final String url;

        public InvalidUrlException(String url, String message) {
            this(url, message, null);
        }

        public InvalidUrlException(String url, String message, Throwable cause) {
            super(message, cause);
            this.url = Objects.requireNonNull(url);
        }

        /**
         * Gets the URL that caused the exception.
         *
         * @return the URL, never {@code null}.
         */
        public String getUrl() {
            return url;
        }
    }
}
