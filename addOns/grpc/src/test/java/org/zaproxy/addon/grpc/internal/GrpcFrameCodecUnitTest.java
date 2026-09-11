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

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

class GrpcFrameCodecUnitTest {

    @Test
    void shouldRejectFrameShorterThanHeader() {
        IllegalArgumentException exception =
                assertThrows(
                        IllegalArgumentException.class,
                        () -> GrpcFrameCodec.decodeUnaryMessage(new byte[] {0, 0, 0, 0}));

        assertTrue(exception.getMessage().contains("expected at least 5 bytes"));
    }

    @Test
    void shouldRejectFrameWithDeclaredLengthLargerThanAvailablePayload() {
        IllegalArgumentException exception =
                assertThrows(
                        IllegalArgumentException.class,
                        () ->
                                GrpcFrameCodec.decodeUnaryMessage(
                                        new byte[] {0, 0, 0, 0, 2, 0x08}));

        assertTrue(exception.getMessage().contains("Truncated gRPC frame"));
    }

    @Test
    void shouldRejectFrameWithTrailingData() {
        IllegalArgumentException exception =
                assertThrows(
                        IllegalArgumentException.class,
                        () ->
                                GrpcFrameCodec.decodeUnaryMessage(
                                        new byte[] {0, 0, 0, 0, 1, 0x08, 0x10}));

        assertTrue(exception.getMessage().contains("Multiple gRPC frames or trailing data"));
    }

    @Test
    void shouldRejectCompressedFrame() {
        IllegalArgumentException exception =
                assertThrows(
                        IllegalArgumentException.class,
                        () -> GrpcFrameCodec.decodeUnaryMessage(new byte[] {1, 0, 0, 0, 0}));

        assertTrue(exception.getMessage().contains("Compressed gRPC messages are not supported"));
    }

    @Test
    void shouldEncodeAndDecodeUnaryUncompressedFrame() {
        byte[] payload = new byte[] {0x0A, 0x01, 0x78};

        byte[] framedMessage = GrpcFrameCodec.encodeUnaryMessage(payload);

        assertArrayEquals(new byte[] {0, 0, 0, 0, 3, 0x0A, 0x01, 0x78}, framedMessage);
        assertArrayEquals(payload, GrpcFrameCodec.decodeUnaryMessage(framedMessage));
    }
}
