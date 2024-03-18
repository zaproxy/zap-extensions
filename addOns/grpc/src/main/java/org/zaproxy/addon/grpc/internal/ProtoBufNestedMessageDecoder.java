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

import com.google.protobuf.CodedInputStream;
import java.io.IOException;

public class ProtoBufNestedMessageDecoder {
    private CodedInputStream inputStream;

    public String startDecoding(byte[] inputData) {
        this.inputStream = CodedInputStream.newInstance(inputData);
        boolean check = true;
        String output = "{";
        while (check) {
            String validField = decodeField();
            if (validField.isEmpty()) return validField;
            else output += "\"" + validField + "\"";
            try {
                if (inputStream.isAtEnd()) {
                    check = false;
                }
            } catch (IOException e) {
                return "";
            }
        }
        output += "}";
        return output;
    }

    private String decodeField() {
        int tag;
        try {
            tag = inputStream.readTag();
            // field number 0 is reserved for error
            if (tag >> 3 == 0) {
                return "";
            }
            return DecoderUtils.decodeField(tag, inputStream);
        } catch (IOException e) {
            return "";
        }
    }
}
