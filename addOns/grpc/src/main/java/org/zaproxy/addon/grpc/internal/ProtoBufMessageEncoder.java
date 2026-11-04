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

import com.google.protobuf.CodedOutputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.List;

public class ProtoBufMessageEncoder {
    private static final byte[] EMPTY_BYTE_ARRAY = new byte[0];
    private ByteArrayOutputStream outputStream;
    private byte[] outputEncodedMessage;

    public void encode(List<String> inputString)
            throws InvalidProtobufFormatException, IOException {
        if (inputString == null) {
            outputStream = null;
            outputEncodedMessage = null;
            return;
        }
        this.outputStream = new ByteArrayOutputStream();
        CodedOutputStream codedOutputStream = CodedOutputStream.newInstance(outputStream);

        try {
            EncoderUtils.writeFields(inputString, codedOutputStream);
            codedOutputStream.flush();
            outputEncodedMessage = GrpcFrameCodec.encodeUnaryMessage(outputStream.toByteArray());
        } catch (Exception e) {
            outputStream.reset();
            outputEncodedMessage = EMPTY_BYTE_ARRAY;
            throw e;
        }
    }

    public byte[] getOutputEncodedMessage() {
        return outputEncodedMessage;
    }
}
