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
package org.zaproxy.zap.extension.spiderAjax;

import java.util.Objects;
import java.util.regex.Pattern;
import org.zaproxy.zap.utils.Enableable;

public class AllowedResource extends Enableable {

    private Pattern pattern;

    public AllowedResource(Pattern pattern) {
        this(pattern, true);
    }

    public AllowedResource(Pattern pattern, boolean enabled) {
        super(enabled);

        this.pattern = Objects.requireNonNull(pattern);
    }

    public AllowedResource(AllowedResource allowedResource) {
        this(allowedResource.pattern, allowedResource.isEnabled());
    }

    public Pattern getPattern() {
        return pattern;
    }

    public void setPattern(Pattern pattern) {
        this.pattern = Objects.requireNonNull(pattern);
    }

    @Override
    public int hashCode() {
        return Objects.hash(pattern, isEnabled());
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!super.equals(obj)) {
            return false;
        }
        if (getClass() != obj.getClass()) {
            return false;
        }
        AllowedResource other = (AllowedResource) obj;
        return pattern.equals(other.pattern);
    }

    /**
     * Creates a {@code Pattern} with default flags for the given regular expression.
     *
     * @param regex the regular expression
     * @return the {@code Pattern} for the given regular expression.
     * @throws IllegalArgumentException if the regular expression is not valid.
     */
    public static Pattern createDefaultPattern(String regex) {
        return Pattern.compile(regex, Pattern.CASE_INSENSITIVE);
    }
}
