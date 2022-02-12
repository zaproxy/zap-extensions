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
package org.zaproxy.addon.network.internal.server.http;

import java.util.Objects;
import java.util.function.Predicate;
import java.util.regex.Pattern;
import org.parosproxy.paros.network.HttpRequestHeader;
import org.zaproxy.zap.utils.Enableable;

/** The pass-through condition of a HTTPS connection. */
public class PassThrough extends Enableable implements Predicate<HttpRequestHeader> {

    private Pattern authority;

    /**
     * Constructs a {@code PassThrough} with the given values.
     *
     * @param authority the authority pattern.
     * @param enabled {@code true} if enabled, {@code false} otherwise.
     * @throws NullPointerException if the given authority is {@code null}.
     */
    public PassThrough(Pattern authority, boolean enabled) {
        super(enabled);
        setAuthority(authority);
    }

    /**
     * Constructs a {@code PassThrough} from the given instance.
     *
     * @param other the other instance.
     * @throws NullPointerException if the given value is {@code null}.
     */
    public PassThrough(PassThrough other) {
        super(Objects.requireNonNull(other).isEnabled());

        this.authority = other.authority;
    }

    /**
     * Gets the authority pattern.
     *
     * @return the authority.
     */
    public Pattern getAuthority() {
        return authority;
    }

    /**
     * Sets the authority pattern.
     *
     * @param authority the authority
     * @throws NullPointerException if the given authority is {@code null}.
     */
    public void setAuthority(Pattern authority) {
        this.authority = Objects.requireNonNull(authority);
    }

    @Override
    public boolean test(HttpRequestHeader requestHeader) {
        if (!isEnabled()) {
            return false;
        }

        String requestedAuthority = requestHeader.getURI().getEscapedAuthority();
        return authority.matcher(requestedAuthority).find();
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = super.hashCode();
        result = prime * result + Objects.hash(authority.pattern());
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
        if (!(obj instanceof PassThrough)) {
            return false;
        }
        PassThrough other = (PassThrough) obj;
        return Objects.equals(authority.pattern(), other.authority.pattern());
    }

    /**
     * Creates the authority pattern.
     *
     * @param value the value of the authority.
     * @return the pattern or {@code null} if the given value is {@code null} or empty.
     * @throws IllegalArgumentException if the given value is not a valid pattern.
     */
    public static Pattern createAuthorityPattern(String value) {
        if (value == null || value.isEmpty()) {
            return null;
        }
        return Pattern.compile(value);
    }
}
