/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2022 The ZAP Development Team
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
package org.zaproxy.addon.network.internal.client;

import java.util.Objects;
import java.util.function.Predicate;
import java.util.regex.Pattern;
import org.zaproxy.zap.utils.Enableable;

/** A HTTP Proxy exclusion. */
public class HttpProxyExclusion extends Enableable implements Predicate<String> {

    private Pattern host;

    /**
     * Constructs a {@code HttpProxyExclusion} with the given values.
     *
     * @param host the host pattern.
     * @param enabled {@code true} if enabled, {@code false} otherwise.
     * @throws NullPointerException if the given host is {@code null}.
     */
    public HttpProxyExclusion(Pattern host, boolean enabled) {
        super(enabled);
        setHost(host);
    }

    /**
     * Constructs a {@code HttpProxyExclusion} from the given instance.
     *
     * @param other the other instance.
     * @throws NullPointerException if the given value is {@code null}.
     */
    public HttpProxyExclusion(HttpProxyExclusion other) {
        super(Objects.requireNonNull(other).isEnabled());

        this.host = other.host;
    }

    /**
     * Gets the host pattern.
     *
     * @return the host.
     */
    public Pattern getHost() {
        return host;
    }

    /**
     * Sets the host pattern.
     *
     * @param host the host
     * @throws NullPointerException if the given host is {@code null}.
     */
    public void setHost(Pattern host) {
        this.host = Objects.requireNonNull(host);
    }

    @Override
    public boolean test(String host) {
        if (!isEnabled()) {
            return false;
        }

        return this.host.matcher(host).find();
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = super.hashCode();
        result = prime * result + Objects.hash(host.pattern());
        return result;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!super.equals(obj)) {
            return false;
        }
        if (!(obj instanceof HttpProxyExclusion)) {
            return false;
        }
        HttpProxyExclusion other = (HttpProxyExclusion) obj;
        return Objects.equals(host.pattern(), other.host.pattern());
    }

    /**
     * Creates the host pattern.
     *
     * @param value the value of the host.
     * @return the pattern or {@code null} if the given value is {@code null} or empty.
     * @throws IllegalArgumentException if the given value is not a valid pattern.
     */
    public static Pattern createHostPattern(String value) {
        if (value == null || value.isEmpty()) {
            return null;
        }
        return Pattern.compile(value, Pattern.CASE_INSENSITIVE);
    }
}
