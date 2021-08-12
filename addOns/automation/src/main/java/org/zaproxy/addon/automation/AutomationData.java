/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2021 The ZAP Development Team
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
package org.zaproxy.addon.automation;

import com.fasterxml.jackson.annotation.JsonFilter;
import java.lang.reflect.Method;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

@JsonFilter("ignoreDefaultFilter")
public abstract class AutomationData {

    private static final Logger LOG = LogManager.getLogger(AutomationData.class);

    public boolean isDefaultValue(String name) {
        String getter = "get" + name.substring(0, 1).toUpperCase() + name.substring(1);
        try {
            Method method = this.getClass().getMethod(getter);
            return method.invoke(this) == null;
        } catch (Exception e) {
            LOG.debug("Class {} no getter {}", this.getClass().getCanonicalName(), getter);
        }
        return false;
    }
}
