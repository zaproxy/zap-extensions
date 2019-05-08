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
package org.zaproxy.zap.extension.websocket.messagelocations;

import org.parosproxy.paros.Constant;
import org.zaproxy.zap.extension.websocket.WebSocketMessageDTO;
import org.zaproxy.zap.model.MessageLocation;

/** A textual {@code MessageLocation} of {@code WebSocket} messages. */
public class TextWebSocketMessageLocation implements WebSocketMessageLocation {

    private final int start;
    private final int end;
    private final String value;

    public TextWebSocketMessageLocation(int position) {
        if (position < 0) {
            throw new IllegalArgumentException(
                    "Parameter position must be greater or equal to zero.");
        }
        this.start = position;
        this.end = position;
        this.value = "";
    }

    public TextWebSocketMessageLocation(int start, int end, String value) {
        if (start < 0) {
            throw new IllegalArgumentException("Parameter start must be greater or equal to zero.");
        }
        if (end < 0) {
            throw new IllegalArgumentException("Parameter end must be greater or equal to zero.");
        }
        if (start > end) {
            throw new IllegalArgumentException("Parameter end must be greater than start.");
        }
        if (value == null) {
            throw new IllegalArgumentException("Parameter value must not be null.");
        }
        this.start = start;
        this.end = end;
        this.value = value;
    }

    @Override
    public Class<WebSocketMessageDTO> getTargetMessageClass() {
        return WebSocketMessageDTO.class;
    }

    @Override
    public String getDescription() {
        StringBuffer description = new StringBuffer(25);
        description.append(Constant.messages.getString("websocket.messagelocation.text.location"));

        description.append(" [").append(start);
        if (start != end) {
            description.append(", ").append(end);
        }
        description.append(']');

        return description.toString();
    }

    @Override
    public String getValue() {
        return value;
    }

    public int getStart() {
        return start;
    }

    public int getEnd() {
        return end;
    }

    @Override
    public boolean overlaps(MessageLocation otherLocation) {
        if (!(otherLocation instanceof TextWebSocketMessageLocation)) {
            return true;
        }

        TextWebSocketMessageLocation otherTextLocation =
                (TextWebSocketMessageLocation) otherLocation;
        if (start == otherTextLocation.getStart()) {
            if (start == end) {
                return end == otherTextLocation.getEnd();
            }
            return otherTextLocation.getStart() != otherTextLocation.getEnd();
        }
        if (start < otherTextLocation.getStart()) {
            return end > otherTextLocation.getStart();
        }
        return start < otherTextLocation.getEnd();
    }

    @Override
    public int compareTo(MessageLocation otherLocation) {
        if (!(otherLocation instanceof TextWebSocketMessageLocation)) {
            return 1;
        }

        TextWebSocketMessageLocation otherTextLocation =
                (TextWebSocketMessageLocation) otherLocation;
        if (start > otherTextLocation.getStart()) {
            return 1;
        } else if (start < otherTextLocation.getStart()) {
            return -1;
        }

        if (end > otherTextLocation.getEnd()) {
            return 1;
        } else if (end < otherTextLocation.getEnd()) {
            return -1;
        }

        int result = value.compareTo(otherTextLocation.getValue());
        if (result != 0) {
            return result;
        }

        return 1;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + end;
        result = prime * result + start;
        result = prime * result + ((value == null) ? 0 : value.hashCode());
        return result;
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
        TextWebSocketMessageLocation other = (TextWebSocketMessageLocation) obj;
        if (end != other.end) {
            return false;
        }
        if (start != other.start) {
            return false;
        }
        if (value == null) {
            if (other.value != null) {
                return false;
            }
        } else if (!value.equals(other.value)) {
            return false;
        }
        return true;
    }
}
