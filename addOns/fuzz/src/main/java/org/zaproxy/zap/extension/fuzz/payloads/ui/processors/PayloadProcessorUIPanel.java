/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2015 The ZAP Development Team
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
package org.zaproxy.zap.extension.fuzz.payloads.ui.processors;

import javax.swing.JPanel;
import org.zaproxy.zap.extension.fuzz.payloads.Payload;
import org.zaproxy.zap.extension.fuzz.payloads.processor.PayloadProcessor;
import org.zaproxy.zap.model.MessageLocation;

public interface PayloadProcessorUIPanel<
        T extends Payload, T2 extends PayloadProcessor<T>, T3 extends PayloadProcessorUI<T, T2>> {

    JPanel getComponent();

    void init(MessageLocation messageLocation);

    void setPayloadProcessorUI(T3 payloadProcessorUI);

    T3 getPayloadProcessorUI();

    T2 getPayloadProcessor();

    void clear();

    boolean validate();

    /**
     * Gets the 'target' to the help page of this payload generator panel. The 'target' must be
     * defined in the {@code map}'s help file. If there's no help available this method should
     * return {@code null}.
     *
     * <p>A help button is shown when the help is available.
     *
     * @return the 'target' to the help page of this payload generator panel, or {@code null} if no
     *     help page is available
     */
    String getHelpTarget();
}
