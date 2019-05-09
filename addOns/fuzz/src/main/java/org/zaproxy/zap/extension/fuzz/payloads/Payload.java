/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2015 The ZAP Development Team
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
package org.zaproxy.zap.extension.fuzz.payloads;

/** A payload used for fuzzing. */
public interface Payload {

    /**
     * Gets value of the payload, as {@code String}.
     *
     * @return the value of the payload.
     */
    String getValue();

    /**
     * Sets value of the payload.
     *
     * <p>Implementations might ignore the value, if not appropriate (for example, if it's a numeric
     * payload but it's being set a String).
     *
     * @param value the new value
     */
    void setValue(Object value);

    /**
     * Returns a copy of this payload.
     *
     * <p>Implementations might opt to return {@code this}, if immutable and thread-safe.
     *
     * @return a new {@code Payload} whose contents are equal to this payload.
     */
    Payload copy();
}
