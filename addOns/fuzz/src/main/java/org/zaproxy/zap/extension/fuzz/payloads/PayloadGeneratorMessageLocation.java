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
package org.zaproxy.zap.extension.fuzz.payloads;

import org.zaproxy.zap.extension.fuzz.messagelocations.MessageLocationReplacementGenerator;
import org.zaproxy.zap.model.MessageLocation;
import org.zaproxy.zap.utils.ResettableAutoCloseableIterator;

/**
 * A {@code MessageLocationReplacement} associated with a iterator of a {@code PayloadGenerator}.
 */
public class PayloadGeneratorMessageLocation<E extends Payload>
        implements MessageLocationReplacementGenerator<E, PayloadMessageLocationReplacement<E>> {

    private final MessageLocation messageLocation;
    private final long numberOfPayloads;
    private final ResettableAutoCloseableIterator<E> payloadIterator;
    private E currentPayload;

    public PayloadGeneratorMessageLocation(
            MessageLocation messageLocation,
            long numberOfPayloads,
            ResettableAutoCloseableIterator<E> payloadIterator) {
        this.messageLocation = messageLocation;
        this.numberOfPayloads = numberOfPayloads;
        this.payloadIterator = payloadIterator;
    }

    @Override
    public MessageLocation getMessageLocation() {
        return messageLocation;
    }

    @Override
    public long getNumberOfReplacements() {
        return numberOfPayloads;
    }

    @Override
    public int compareTo(MessageLocationReplacementGenerator<?, ?> other) {
        if (other == null) {
            return 1;
        }
        return messageLocation.compareTo(other.getMessageLocation());
    }

    @Override
    public int hashCode() {
        return 31 + ((messageLocation == null) ? 0 : messageLocation.hashCode());
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null) {
            return false;
        }
        if (getClass() != obj.getClass()) {
            return false;
        }
        PayloadGeneratorMessageLocation<?> other = (PayloadGeneratorMessageLocation<?>) obj;
        if (messageLocation == null) {
            if (other.messageLocation != null) {
                return false;
            }
        } else if (!messageLocation.equals(other.messageLocation)) {
            return false;
        }
        return true;
    }

    @Override
    public boolean hasNext() {
        return payloadIterator.hasNext();
    }

    @Override
    public PayloadMessageLocationReplacement<E> next() {
        currentPayload = payloadIterator.next();
        return new PayloadMessageLocationReplacement<>(messageLocation, currentPayload);
    }

    @Override
    public void remove() {}

    @Override
    public void reset() {
        payloadIterator.reset();
    }

    @Override
    public void close() {
        payloadIterator.close();
    }
}
