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

import org.zaproxy.zap.extension.fuzz.FuzzerMessageProcessor;
import org.zaproxy.zap.extension.fuzz.FuzzerMessageProcessorUI;
import org.zaproxy.zap.extension.httppanel.Message;
import org.zaproxy.zap.utils.Orderable;

public class FuzzerMessageProcessorTableEntry<
                T1 extends Message, T2 extends FuzzerMessageProcessor<T1>>
        implements Orderable {

    private int order;
    private FuzzerMessageProcessorUI<T1, T2> messageProcessorUI;

    public FuzzerMessageProcessorTableEntry(
            int order, FuzzerMessageProcessorUI<T1, T2> messageProcessorUI) {
        this.order = order;
        this.messageProcessorUI = messageProcessorUI;
    }

    public void setFuzzerMessageProcessorUI(FuzzerMessageProcessorUI<T1, T2> messageProcessorUI) {
        this.messageProcessorUI = messageProcessorUI;
    }

    public FuzzerMessageProcessorUI<T1, T2> getFuzzerMessageProcessorUI() {
        return messageProcessorUI;
    }

    @Override
    public void setOrder(int order) {
        this.order = order;
    }

    @Override
    public int getOrder() {
        return order;
    }

    public String getName() {
        return messageProcessorUI.getName();
    }

    public String getDescription() {
        return messageProcessorUI.getDescription();
    }

    public FuzzerMessageProcessorTableEntry<T1, T2> copy() {
        return new FuzzerMessageProcessorTableEntry<>(order, messageProcessorUI);
    }

    public boolean isMutable() {
        return messageProcessorUI.isMutable();
    }
}
