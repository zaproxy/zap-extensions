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

import org.zaproxy.zap.extension.fuzz.messagelocations.MessageLocationReplacement;
import org.zaproxy.zap.model.MessageLocation;

/**
 * A {@code MessageLocationReplacement} with a {@code Payload}.
 *
 * @param <T> the type of payloads used during replacement
 * @see MessageLocationReplacement
 */
public class PayloadMessageLocationReplacement<T extends Payload>
        implements MessageLocationReplacement<T> {

    private final MessageLocation messageLocation;
    private final T payload;

    public PayloadMessageLocationReplacement(MessageLocation messageLocation, T payload) {
        this.messageLocation = messageLocation;
        this.payload = payload;
    }

    @Override
    public MessageLocation getMessageLocation() {
        return messageLocation;
    }

    @Override
    public T getReplacement() {
        return payload;
    }

    @Override
    public int compareTo(MessageLocationReplacement<?> other) {
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
        PayloadMessageLocationReplacement<?> other = (PayloadMessageLocationReplacement<?>) obj;
        if (messageLocation == null) {
            if (other.messageLocation != null) {
                return false;
            }
        } else if (!messageLocation.equals(other.messageLocation)) {
            return false;
        }
        return true;
    }
}
