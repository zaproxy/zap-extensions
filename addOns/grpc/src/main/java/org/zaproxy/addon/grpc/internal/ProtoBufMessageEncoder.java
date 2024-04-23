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
import java.nio.ByteBuffer;
import java.util.List;

public class ProtoBufMessageEncoder {
    private static final int HEADER_LENGTH = 5;

    private static byte[] EMPTY_BYTE_ARRAY = new byte[0];
    private ByteArrayOutputStream outputStream;
    private byte[] outputEncodedMessage;
    private ByteBuffer headerScratch;
    private int totalEncodedMessageSize;

    public void encode(List<String> inputString)
            throws InvalidProtobufFormatException, IOException {
        if (inputString == null || inputString.isEmpty()) {
            return;
        }
        this.outputStream = new ByteArrayOutputStream();
        CodedOutputStream codedOutputStream = CodedOutputStream.newInstance(outputStream);
        headerScratch = ByteBuffer.allocate(HEADER_LENGTH);

        try {
            final int bufferSize = EncoderUtils.getSerializedSize(inputString);
            totalEncodedMessageSize = bufferSize + HEADER_LENGTH;
            writeHeader();
            EncoderUtils.writeFields(inputString, codedOutputStream);
            codedOutputStream.flush();
            setOutputEncodedMessage();
        } catch (Exception e) {
            outputStream.reset();
            outputEncodedMessage = EMPTY_BYTE_ARRAY;
            throw e;
        }

        return;
    }

    private void writeHeader() {
        headerScratch.clear();
        headerScratch.put((byte) 0).putInt(totalEncodedMessageSize - HEADER_LENGTH);
        outputStream.write(headerScratch.array(), 0, headerScratch.position());
    }

    public byte[] getOutputEncodedMessage() {
        return outputEncodedMessage;
    }

    private void setOutputEncodedMessage() {
        byte[] outputStreamBytes = outputStream.toByteArray();
        outputEncodedMessage = new byte[totalEncodedMessageSize];
        for (int i = 0; i < totalEncodedMessageSize; i++) {
            outputEncodedMessage[i] = outputStreamBytes[i];
        }
    }
}
