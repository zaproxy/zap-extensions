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
package org.zaproxy.zap.extension.scripts.scanrules;

import javax.script.ScriptException;
import net.htmlparser.jericho.Source;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.pscan.PluginPassiveScanner;

public interface PassiveScript {

    void scan(PassiveScriptHelper helper, HttpMessage msg, Source source) throws ScriptException;

    /**
     * Tells whether the scanner applies to the given history type.
     *
     * <p>By default it scans the {@link PluginPassiveScanner#getDefaultHistoryTypes() default
     * history types}.
     *
     * @param historyType the history type of the message to be scanned.
     * @return {@code true} if the scanner applies to the given history type, {@code false}
     *     otherwise.
     */
    default boolean appliesToHistoryType(int historyType) {
        return PluginPassiveScanner.getDefaultHistoryTypes().contains(historyType);
    }
}
