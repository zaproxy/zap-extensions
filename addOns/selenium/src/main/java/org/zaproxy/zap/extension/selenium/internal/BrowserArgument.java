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
package org.zaproxy.zap.extension.selenium.internal;

import java.util.Objects;
import org.zaproxy.zap.utils.EnableableInterface;

public class BrowserArgument implements EnableableInterface {

    private boolean enabled;
    private String argument;

    public BrowserArgument(String argument, boolean enabled) {
        this.enabled = enabled;
        setArgument(argument);
    }

    public BrowserArgument(BrowserArgument other) {
        this(other.argument, other.enabled);
    }

    @Override
    public boolean isEnabled() {
        return enabled;
    }

    @Override
    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    public String getArgument() {
        return argument;
    }

    public void setArgument(String argument) {
        this.argument = Objects.requireNonNull(argument).trim();
    }

    @Override
    public int hashCode() {
        return Objects.hash(argument, enabled);
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof BrowserArgument)) {
            return false;
        }
        BrowserArgument other = (BrowserArgument) obj;
        return enabled == other.enabled && Objects.equals(argument, other.argument);
    }
}
