/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2012 The ZAP Development Team
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
package org.zaproxy.zap.extension.websocket;

import java.nio.charset.StandardCharsets;
import java.sql.Timestamp;
import java.text.SimpleDateFormat;
import java.util.HashMap;
import java.util.Map;
import net.sf.json.JSONException;
import net.sf.json.JSONSerializer;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.lang.time.FastDateFormat;
import org.apache.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.zaproxy.zap.extension.httppanel.Message;
import org.zaproxy.zap.extension.websocket.utility.InvalidUtf8Exception;
import org.zaproxy.zap.extension.websocket.utility.Utf8Util;

/**
 * Data Transfer Object used for displaying WebSockets communication. Intended to decouple user
 * interface representation from version specific {@link WebSocketMessage}.
 */
public class WebSocketMessageDTO implements Message {

    /** Each message is sent on a specific connection. Ensure that it is not <code>null</code>! */
    public WebSocketChannelDTO channel;

    /** Consecutive number for each message unique for one given channel. */
    public Integer id;

    /** Used for sorting, containing time of arrival in milliseconds. */
    public Long timestamp;

    /** When the message was finished (it might consist of several frames). */
    public String dateTime;

    /**
     * You can retrieve a textual version of this opcode via: {@link
     * WebSocketMessage#opcode2string(int)}.
     */
    public Integer opcode;

    /** Textual representation of {@link WebSocketMessageDTO#opcode}. */
    public String readableOpcode;

    /**
     * Might be either a string (readable representation for TEXT frames) OR byte[].
     *
     * <p>If it is a byte[] then it might be readable though.
     */
    public Object payload;

    /** For close messages, there is always a reason. */
    public Integer closeCode;

    /** Outgoing or incoming message. */
    public Boolean isOutgoing;

    /** Number of the payload bytes. */
    public Integer payloadLength;

    /** Temporary object holding arbitrary values. */
    public volatile Object tempUserObj;

    /** Used to format {@link WebSocketMessage#timestamp} in user's locale. */
    protected static final FastDateFormat dateFormatter;

    /**
     * Marks this object as changed, indicating that frame headers have to be built manually on
     * forwarding.
     */
    public boolean hasChanged;

    /** Use the static initializer for setting up one date formatter for all instances. */
    static {
        // milliseconds are added later (via usage java.sql.Timestamp.getNanos())
        dateFormatter =
                FastDateFormat.getDateTimeInstance(
                        SimpleDateFormat.SHORT, SimpleDateFormat.MEDIUM, Constant.getLocale());
    }

    private static final Logger LOG = Logger.getLogger(WebSocketMessageDTO.class);

    /** @param channel */
    public WebSocketMessageDTO(WebSocketChannelDTO channel) {
        this.channel = channel;
    }

    public WebSocketMessageDTO() {
        this(new WebSocketChannelDTO());
    }

    /**
     * Helper to set {@link WebSocketMessageDTO#timestamp} and {@link WebSocketMessageDTO#dateTime}.
     *
     * @param ts
     */
    public void setTime(Timestamp ts) {
        timestamp = ts.getTime() + (ts.getNanos() / 1000000000);

        synchronized (dateFormatter) {
            dateTime = dateFormatter.format(ts);
        }

        String nanos = Integer.toString(ts.getNanos()).replaceAll("0+$", "");
        if (nanos.length() == 0) {
            nanos = "0";
        }

        dateTime = dateTime.replaceFirst("([0-9]+:[0-9]+:[0-9]+)", "$1." + nanos);
    }

    @Override
    public String toString() {
        if (channel.id != null && id != null) {
            return "#" + channel.id + "." + id;
        }
        return "";
    }

    /**
     * Assigns all values to given object.
     *
     * @param other
     */
    public void copyInto(WebSocketMessageDTO other) {
        other.channel = this.channel;
        other.closeCode = this.closeCode;
        other.dateTime = this.dateTime;
        other.isOutgoing = this.isOutgoing;
        other.id = this.id;
        other.opcode = this.opcode;
        other.payload = this.payload;
        other.payloadLength = this.payloadLength;
        other.readableOpcode = this.readableOpcode;
        other.tempUserObj = this.tempUserObj;
        other.timestamp = this.timestamp;
    }

    @Override
    public boolean isInScope() {
        if (channel == null) {
            return false;
        }
        return channel.isInScope();
    }

    /**
     * Returns content of {@link WebSocketMessageDTO#payload} directly if it is of type {@link
     * String}. Otherwise it tries to convert it.
     *
     * @return readable representation of payload
     * @throws InvalidUtf8Exception
     */
    public String getReadablePayload() throws InvalidUtf8Exception {
        if (payload instanceof String) {
            return (String) payload;
        } else if (payload instanceof byte[]) {
            return Utf8Util.encodePayloadToUtf8((byte[]) payload);
        } else {
            return "";
        }
    }

    /**
     * Returns content of {@link WebSocketMessageDTO#payload} directly if it is of type {@link
     * String}. Otherwise tries to convert that by replacing unmapped &amp; malformed characters.
     *
     * @return readable representation of payload
     */
    public String getPayloadAsString() {
        if (payload instanceof String) {
            return (String) payload;
        } else if (payload instanceof byte[]) {
            return new String((byte[]) payload, StandardCharsets.UTF_8);
        } else {
            return "";
        }
    }

    @Override
    public boolean isForceIntercept() {
        // Not currently supported for WebSockets
        return false;
    }

    public Map<String, String> toMap(boolean fullPayload) {
        Map<String, String> map = new HashMap<String, String>();
        map.put("id", Integer.toString(this.id));
        map.put("opcode", Integer.toString(this.opcode));
        map.put("opcodeString", this.readableOpcode);
        map.put("timestamp", Long.toString(this.timestamp));
        map.put("outgoing", Boolean.toString(this.isOutgoing));
        map.put("channelId", Integer.toString(this.channel.id));
        map.put("channelHost", this.channel.host);
        map.put("thisId", Integer.toString(this.id));
        map.put("payloadLength", Integer.toString(this.payloadLength));
        if (fullPayload) {
            if (this.payload instanceof String) {
                String payload = (String) this.payload;
                try {
                    JSONSerializer.toJSON(payload);
                    // Its valid JSON so escape
                    map.put("payload", "'" + payload + "'");
                } catch (JSONException e) {
                    // Its not a valid JSON object so can add as is
                    map.put("payload", payload);
                }
            } else if (this.payload instanceof byte[]) {
                map.put("payload", Hex.encodeHexString((byte[]) this.payload));
            } else {
                try {
                    map.put("payload", this.getReadablePayload());
                } catch (InvalidUtf8Exception e) {
                    LOG.error(e.getMessage(), e);
                }
            }
        } else {
            try {
                String payloadFragment = this.getReadablePayload();
                map.put("payloadFragment", payloadFragment);
            } catch (InvalidUtf8Exception e) {
                // Ignore as its just a summary
            }
        }
        return map;
    }

    @Override
    public Map<String, String> toEventData() {
        return this.toMap(true);
    }
}
