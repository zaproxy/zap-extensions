/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2026 The ZAP Development Team
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
package org.zaproxy.addon.commonlib;

/**
 * Thrown when a string is not a valid, absolute URL with a supported scheme.
 *
 * @since 1.43.0
 */
public class ZapUriException extends Exception {

    private static final long serialVersionUID = 1L;

    private final String input;

    public ZapUriException(String input, Throwable cause) {
        super(cause.getMessage(), cause);
        this.input = input;
    }

    public ZapUriException(String message) {
        super(message);
        this.input = null;
    }

    /** Returns the URL string that failed validation. */
    public String getInput() {
        return input;
    }
}
