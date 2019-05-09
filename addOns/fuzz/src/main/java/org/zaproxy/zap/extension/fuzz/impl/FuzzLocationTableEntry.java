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

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import org.zaproxy.zap.model.MessageLocation;
import org.zaproxy.zap.view.messagelocation.MessageLocationHighlight;
import org.zaproxy.zap.view.messagelocation.MessageLocationTableEntry;

public class FuzzLocationTableEntry extends MessageLocationTableEntry {

    private List<PayloadTableEntry> payloads;
    private int numberOfPayloads;
    private List<PayloadProcessorTableEntry> processors;

    public FuzzLocationTableEntry(MessageLocation location, List<PayloadTableEntry> payloads) {
        super(location);

        this.processors = Collections.emptyList();
        setPayloads(payloads);
    }

    public FuzzLocationTableEntry(
            MessageLocation location,
            MessageLocationHighlight highlight,
            MessageLocationHighlight highlightReference,
            List<PayloadTableEntry> payloads) {
        super(location, highlight, highlightReference);

        this.processors = Collections.emptyList();
        setPayloads(payloads);
    }

    public void setPayloads(List<PayloadTableEntry> payloads) {
        this.payloads = new ArrayList<>(payloads);

        numberOfPayloads = 0;
        for (PayloadTableEntry payloadTableEntry : payloads) {
            numberOfPayloads += payloadTableEntry.getPayloadGeneratorUI().getNumberOfPayloads();
        }
    }

    public List<PayloadTableEntry> getPayloads() {
        return payloads;
    }

    public int getNumberOfPayloads() {
        return numberOfPayloads;
    }

    public void setProcessors(List<PayloadProcessorTableEntry> processors) {
        this.processors = processors;
    }

    public List<PayloadProcessorTableEntry> getProcessors() {
        return processors;
    }
}
