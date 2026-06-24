/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2024 The ZAP Development Team
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
package org.zaproxy.addon.grpc.internal;

import com.google.protobuf.InvalidProtocolBufferException;
import com.google.protobuf.UnknownFieldSet;
import java.util.ArrayList;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;

public class ProtoBufMessageDecoder {

    private static final Logger LOGGER = LogManager.getLogger(ProtoBufMessageDecoder.class);

    private List<String> decodedToList;
    private StringBuilder decodedToString;

    public ProtoBufMessageDecoder() {
        this.decodedToList = new ArrayList<>();
        this.decodedToString = new StringBuilder();
    }

    public void decode(byte[] inputEncodedData) {
        decodedToList.clear();
        decodedToString.setLength(0);
        if (inputEncodedData == null || inputEncodedData.length == 0) {
            return;
        }
        try {
            UnknownFieldSet fields = UnknownFieldSet.parseFrom(inputEncodedData);
            decodedToList.addAll(ZapProtoTextCodec.formatToList(fields));
            for (String line : decodedToList) {
                decodedToString.append(line).append('\n');
            }
        } catch (InvalidProtocolBufferException e) {
            LOGGER.debug("Error decoding the message: {}", e.getMessage());
            throw new IllegalArgumentException(Constant.messages.getString("grpc.decoder.error"));
        }
    }

    public String getDecodedOutput() {
        return decodedToString.toString();
    }

    public List<String> getDecodedToList() {
        return decodedToList;
    }
}
