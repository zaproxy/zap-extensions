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
package org.zaproxy.zap.extension.pscan;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import org.parosproxy.paros.model.HistoryReference;
import org.parosproxy.paros.network.HttpMessage;

public final class PassiveScanTestHelper {

    private PassiveScanTestHelper() {}

    public static void init(
            PluginPassiveScanner rule,
            PassiveScanThread parent,
            HttpMessage message,
            PassiveScanData passiveScanData) {
        HistoryReference historyRef = mock(HistoryReference.class);
        when(historyRef.getHistoryId()).thenReturn(1);
        message.setHistoryRef(historyRef);
        rule.init(parent, message, passiveScanData);
    }
}
