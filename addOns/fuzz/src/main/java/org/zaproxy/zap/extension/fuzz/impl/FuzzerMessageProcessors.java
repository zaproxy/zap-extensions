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
package org.zaproxy.zap.extension.fuzz.impl;

import java.util.Collection;
import java.util.List;
import org.zaproxy.zap.extension.fuzz.FuzzerMessageProcessor;
import org.zaproxy.zap.extension.fuzz.FuzzerMessageProcessorUI;
import org.zaproxy.zap.extension.fuzz.FuzzerMessageProcessorUIPanel;
import org.zaproxy.zap.extension.httppanel.Message;

public interface FuzzerMessageProcessors<
        T1 extends Message, T2 extends FuzzerMessageProcessor<T1>> {

    boolean isEmpty();

    FuzzerMessageProcessorUIPanel<T1, T2, ?> getPanel(String name);

    <T3 extends FuzzerMessageProcessorUI<T1, T2>>
            FuzzerMessageProcessorUIPanel<T1, T2, T3> getPanel(T3 fuzzerMessageProcessorUI);

    FuzzerMessageProcessorUIPanel<T1, T2, ?> getDefaultPanel();

    List<? extends FuzzerMessageProcessorUI<T1, T2>> getDefaultProcessors();

    String getDefaultPanelName();

    Collection<String> getFuzzerMessageProcessorUIHandlersNames();

    Collection<? extends FuzzerMessageProcessorUIPanel<T1, T2, ?>> getPanels();
}
