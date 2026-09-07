/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2026 The ZAP Development Team
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

import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.Objects;

/**
 * Encodes and validates the five-byte message framing used by native gRPC.
 *
 * <p>The add-on currently supports unary, uncompressed native gRPC messages. gRPC-Web framing is
 * intentionally handled separately because gRPC-Web responses may contain a trailer frame in the
 * response body.
 */
final class GrpcFrameCodec {

    static final int HEADER_LENGTH = 5;

    private GrpcFrameCodec() {}

    static byte[] decodeUnaryMessage(byte[] framedMessage) {
        Objects.requireNonNull(framedMessage, "framedMessage");

        if (framedMessage.length < HEADER_LENGTH) {
            throw new IllegalArgumentException(
                    "Invalid gRPC frame: expected at least "
                            + HEADER_LENGTH
                            + " bytes but received "
                            + framedMessage.length);
        }

        int compressionFlag = framedMessage[0] & 0xFF;
        if (compressionFlag != 0) {
            throw new IllegalArgumentException(
                    "Compressed gRPC messages are not supported (compression flag="
                            + compressionFlag
                            + ")");
        }

        long declaredLength =
                ((long) (framedMessage[1] & 0xFF) << 24)
                        | ((long) (framedMessage[2] & 0xFF) << 16)
                        | ((long) (framedMessage[3] & 0xFF) << 8)
                        | (long) (framedMessage[4] & 0xFF);
        int availableLength = framedMessage.length - HEADER_LENGTH;

        if (declaredLength > availableLength) {
            throw new IllegalArgumentException(
                    "Truncated gRPC frame: declared payload length "
                            + declaredLength
                            + " but only "
                            + availableLength
                            + " bytes are available");
        }
        if (declaredLength < availableLength) {
            throw new IllegalArgumentException(
                    "Multiple gRPC frames or trailing data are not supported: declared payload length "
                            + declaredLength
                            + " but "
                            + availableLength
                            + " bytes are available");
        }

        return Arrays.copyOfRange(framedMessage, HEADER_LENGTH, framedMessage.length);
    }

    static byte[] encodeUnaryMessage(byte[] payload) {
        Objects.requireNonNull(payload, "payload");
        return ByteBuffer.allocate(HEADER_LENGTH + payload.length)
                .put((byte) 0)
                .putInt(payload.length)
                .put(payload)
                .array();
    }
}
