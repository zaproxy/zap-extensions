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

import com.google.protobuf.UnknownFieldSet;
import java.util.Base64;
import java.util.stream.Stream;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

class ZapProtoTextRoundTripUnitTest {

    private final ProtoBufMessageDecoder decoder = new ProtoBufMessageDecoder();
    private final ProtoBufMessageEncoder encoder = new ProtoBufMessageEncoder();

    static Stream<Arguments> validPayloadFixtures() {
        return Stream.of(
                Arguments.of(
                        "simple valid input",
                        "AAAAADEKC2pvaG4gTWlsbGVyEB4aIDEyMzQgTWFpbiBTdC4gQW55dG93biwgVVNBIDEyMzQ1"),
                Arguments.of(
                        "nested message",
                        "AAAAAEEKEEhlbGxvLCBQcm90b2J1ZiESJwoESm9obhIGTWlsbGVyGhcKBEpvaG4QAhoNCgtIZWxsbyBXb3JsZBjqrcDlJA"),
                Arguments.of("enum and repeated fields", "AAAAAA4IARIBYRIBYhIBYxIBZA"),
                Arguments.of("double and float", "AAAAAA4JzczMzMzcXkAVrseHQg"),
                Arguments.of("wire type 1 and 5", "AAAAAA4NQEIPABHMm5cAyicBAA"));
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("validPayloadFixtures")
    void shouldRoundTripBytesToTextToBytes(String name, String base64Input) throws Exception {
        byte[] payload = payloadFromBase64(base64Input);

        UnknownFieldSet fields = UnknownFieldSet.parseFrom(payload);
        assertArrayEquals(payload, fields.toByteArray(), name + " (wire)");

        decoder.decode(payload);
        encoder.encode(EncoderUtils.parseIntoList(decoder.getDecodedOutput()));
        byte[] roundTripPayload = DecoderUtils.extractPayload(encoder.getOutputEncodedMessage());

        assertArrayEquals(payload, roundTripPayload, name);
    }

    private static byte[] payloadFromBase64(String base64Input) {
        byte[] body = Base64.getDecoder().decode(base64Input);
        return DecoderUtils.extractPayload(body);
    }
}
