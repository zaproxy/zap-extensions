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
package org.zaproxy.zap.extension.spiderAjax.automation;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonInclude.Include;
import org.zaproxy.zap.extension.spiderAjax.internal.ExcludedElement;

/**
 * An {@link ExcludedElement} in an automation plan.
 *
 * <p>Always enabled and with custom serialisation configuration.
 */
@JsonInclude(value = Include.NON_EMPTY, content = Include.NON_EMPTY)
public class ExcludedElementAuto extends ExcludedElement {

    @Override
    @JsonIgnore
    public boolean isEnabled() {
        return true;
    }
}
