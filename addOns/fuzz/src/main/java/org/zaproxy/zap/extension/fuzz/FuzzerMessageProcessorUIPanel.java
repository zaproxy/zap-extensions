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
package org.zaproxy.zap.extension.fuzz;

import javax.swing.JPanel;
import org.zaproxy.zap.extension.httppanel.Message;

public interface FuzzerMessageProcessorUIPanel<
        T1 extends Message,
        T2 extends FuzzerMessageProcessor<T1>,
        T3 extends FuzzerMessageProcessorUI<T1, T2>> {

    void init(T1 message);

    JPanel getComponent();

    void setFuzzerMessageProcessorUI(T3 payloadProcessorUI);

    T3 getFuzzerMessageProcessorUI();

    boolean validate();

    void clear();

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
