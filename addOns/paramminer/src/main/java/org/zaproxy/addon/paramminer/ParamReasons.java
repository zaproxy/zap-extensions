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
package org.zaproxy.addon.paramminer;

import java.util.Map;
import org.zaproxy.addon.paramminer.ParamGuessResult.Reason;

public class ParamReasons {
    private Reason reason;
    private Map<String, String> params;

    public ParamReasons(Reason reason, Map<String, String> params) {
        this.reason = reason;
        this.params = params;
    }

    public Reason getReason() {
        return reason;
    }

    public Map<String, String> getParams() {
        return params;
    }

    public void setReason(Reason reason) {
        this.reason = reason;
    }

    public void setParams(Map<String, String> params) {
        this.params = params;
    }
}
