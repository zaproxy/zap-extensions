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
import org.parosproxy.paros.network.HttpRequestHeader;
import org.zaproxy.zap.utils.Enableable;

/** An alias of a local server. */
public class Alias extends Enableable implements Predicate<HttpRequestHeader> {

    private String name;

    /**
     * Constructs an {@code Alias} with the given values.
     *
     * @param name the name of the alias.
     * @param enabled {@code true} if enabled, {@code false} otherwise.
     * @throws NullPointerException if the given name is {@code null}.
     */
    public Alias(String name, boolean enabled) {
        super(enabled);
        setName(name);
    }

    /**
     * Constructs an {@code Alias} from the given instance.
     *
     * @param other the other instance.
     * @throws NullPointerException if the given value is {@code null}.
     */
    public Alias(Alias other) {
        super(Objects.requireNonNull(other).isEnabled());

        this.name = other.name;
    }

    /**
     * Gets the name.
     *
     * @return the name of the alias.
     */
    public String getName() {
        return name;
    }

    /**
     * Sets the name.
     *
     * @param name the name of the alias.
     * @throws NullPointerException if the given name is {@code null}.
     */
    public void setName(String name) {
        this.name = Objects.requireNonNull(name);
    }

    @Override
    public boolean test(HttpRequestHeader requestHeader) {
        if (!isEnabled()) {
            return false;
        }

        return name.equals(requestHeader.getHostName());
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = super.hashCode();
        result = prime * result + Objects.hash(name);
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
        if (!(obj instanceof Alias)) {
            return false;
        }
        Alias other = (Alias) obj;
        return Objects.equals(name, other.name);
    }
}
