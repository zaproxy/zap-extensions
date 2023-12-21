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
package org.zaproxy.zap.testutils;

import java.util.function.Function;

class AlertReferenceError {

    enum Cause {
        INVALID_URI(e -> "Invalid URI: '" + e.reference + "'. Reason: " + e.detail),
        NOT_HTTPS(e -> "Not HTTPS: " + e.reference),
        NOT_LINK(e -> "Not link: " + e.reference),
        UNEXPECTED_STATUS_CODE(
                e -> "Unexpected status code, 200 != " + e.detail + ", for: " + e.reference),
        IO_EXCEPTION(e -> "I/O exception: " + e.detail + ", for: " + e.reference);

        private final Function<AlertReferenceError, String> toString;

        private Cause(Function<AlertReferenceError, String> toString) {
            this.toString = toString;
        }

        AlertReferenceError create(String reference, Object detail) {
            return new AlertReferenceError(this, reference, detail);
        }

        private String toString(AlertReferenceError error) {
            return toString.apply(error);
        }
    }

    private final Cause cause;
    private final String reference;
    private final Object detail;

    private AlertReferenceError(Cause cause, String reference, Object detail) {
        this.cause = cause;
        this.reference = reference;
        this.detail = detail;
    }

    @Override
    public String toString() {
        return cause.toString(this);
    }
}
