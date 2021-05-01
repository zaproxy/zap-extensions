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

import java.util.Collections;
import java.util.List;
import org.zaproxy.zap.extension.fuzz.payloads.Payload;
import org.zaproxy.zap.extension.fuzz.payloads.generator.PayloadGenerator;
import org.zaproxy.zap.extension.fuzz.payloads.ui.PayloadGeneratorUI;
import org.zaproxy.zap.utils.Orderable;

public class PayloadTableEntry implements Orderable {

    private int order;
    private PayloadGeneratorUI<? extends Payload, ? extends PayloadGenerator<? extends Payload>>
            payloadGeneratorUI;
    private List<PayloadProcessorTableEntry> payloadProcessors;

    public PayloadTableEntry(
            int order,
            PayloadGeneratorUI<? extends Payload, ? extends PayloadGenerator<? extends Payload>>
                    payloadGeneratorUI) {
        this.order = order;

        this.payloadGeneratorUI = payloadGeneratorUI;
        this.payloadProcessors = Collections.emptyList();
    }

    public void setPayloadGeneratorUI(
            PayloadGeneratorUI<? extends Payload, ? extends PayloadGenerator<? extends Payload>>
                    payloadGeneratorUI) {
        this.payloadGeneratorUI = payloadGeneratorUI;
    }

    public PayloadGeneratorUI<? extends Payload, ? extends PayloadGenerator<? extends Payload>>
            getPayloadGeneratorUI() {
        return payloadGeneratorUI;
    }

    @Override
    public int getOrder() {
        return order;
    }

    @Override
    public void setOrder(int order) {
        this.order = order;
    }

    public String getType() {
        return payloadGeneratorUI.getName();
    }

    public String getDescription() {
        return payloadGeneratorUI.getDescription();
    }

    public List<PayloadProcessorTableEntry> getPayloadProcessors() {
        return payloadProcessors;
    }

    public void setPayloadProcessors(List<PayloadProcessorTableEntry> processors) {
        this.payloadProcessors = processors;
    }

    public PayloadTableEntry copy() {
        PayloadTableEntry copy = new PayloadTableEntry(order, payloadGeneratorUI);
        copy.payloadProcessors = payloadProcessors;
        return copy;
    }
}
