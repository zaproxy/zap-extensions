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
package org.zaproxy.addon.paramdigger;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import org.zaproxy.addon.paramdigger.ParamGuessResult.Reason;

public class ParamReasons {
    private List<Reason> reasons;
    private Map<String, String> params;

    public ParamReasons(List<Reason> reasons, Map<String, String> params) {
        this.reasons = Objects.requireNonNull(reasons);
        this.params = params;
    }

    public boolean isEmpty() {
        return this.reasons.isEmpty();
    }

    public ParamReasons() {
        this.reasons = new ArrayList<>();
    }

    public List<Reason> getReasons() {
        return this.reasons;
    }

    public Map<String, String> getParams() {
        return params;
    }

    public void addReason(Reason reason) {
        this.reasons.add(reason);
    }

    public void setReasons(List<Reason> reasons) {
        this.reasons = Objects.requireNonNull(reasons);
    }

    public void setParams(Map<String, String> params) {
        this.params = params;
    }
}
