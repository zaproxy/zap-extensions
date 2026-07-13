/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2026 The ZAP Development Team
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
package org.zaproxy.zap.extension.scripts.automation;

import java.util.Locale;
import org.parosproxy.paros.Constant;
import org.zaproxy.addon.automation.AutomationProgress;

public enum FailureLevel {
    INFO {
        @Override
        public void report(AutomationProgress progress, String message) {
            progress.info(message);
        }
    },
    WARNING {
        @Override
        public void report(AutomationProgress progress, String message) {
            progress.warn(message);
        }
    },
    ERROR {
        @Override
        public void report(AutomationProgress progress, String message) {
            progress.error(message);
        }
    };

    public abstract void report(AutomationProgress progress, String message);

    @Override
    public String toString() {
        return Constant.messages.getString(
                "scripts.automation.failurelevel." + name().toLowerCase(Locale.ROOT));
    }
}
