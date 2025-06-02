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

import org.zaproxy.zap.extension.fuzz.payloads.Payload;
import org.zaproxy.zap.extension.fuzz.payloads.processor.PayloadProcessor;
import org.zaproxy.zap.extension.fuzz.payloads.ui.processors.PayloadProcessorUI;
import org.zaproxy.zap.utils.Orderable;

public class PayloadProcessorTableEntry implements Orderable {

    private int order;
    private PayloadProcessorUI<?, ?> payloadProcessorUI;

    public PayloadProcessorTableEntry(int order, PayloadProcessorUI<?, ?> payloadProcessorUI) {
        this.order = order;
        this.payloadProcessorUI = payloadProcessorUI;
    }

    @Override
    public int getOrder() {
        return order;
    }

    @Override
    public void setOrder(int order) {
        this.order = order;
    }

    public PayloadProcessorUI<? extends Payload, ? extends PayloadProcessor<? extends Payload>>
            getPayloadProcessorUI() {
        return payloadProcessorUI;
    }

    public void setPayloadProcessorUI(PayloadProcessorUI<?, ?> payloadProcessorUI) {
        this.payloadProcessorUI = payloadProcessorUI;
    }

    public String getType() {
        return payloadProcessorUI.getName();
    }

    public String getDescription() {
        return payloadProcessorUI.getDescription();
    }

    public PayloadProcessorTableEntry copy() {
        return new PayloadProcessorTableEntry(order, payloadProcessorUI);
    }

    public boolean isMutable() {
        return payloadProcessorUI.isMutable();
    }
}
