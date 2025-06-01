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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.Base64;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.zaproxy.addon.grpc.ExtensionGrpc;
import org.zaproxy.zap.testutils.TestUtils;

class ProtoBufMessageDecoderUnitTest extends TestUtils {

    private ProtoBufMessageDecoder decoder;

    @BeforeEach
    void setUp() {
        decoder = new ProtoBufMessageDecoder();
    }

    @Test
    void shouldDecodeWithEmptyInput() {
        byte[] emptyInput = new byte[0];
        decoder.decode(emptyInput);
        assertEquals("", decoder.getDecodedOutput());
        assertEquals(0, decoder.getDecodedToList().size());
    }

    @Test
    void shouldDecodeWithNullInput() {
        decoder.decode(null);
        assertEquals("", decoder.getDecodedOutput());
        assertEquals(0, decoder.getDecodedToList().size());
    }

    @Test
    void shouldDecodeWithSimpleValidInput() {
        String inputString =
                "AAAAADEKC2pvaG4gTWlsbGVyEB4aIDEyMzQgTWFpbiBTdC4gQW55dG93biwgVVNBIDEyMzQ1";
        String expectedOutput =
                "1:2::\"john Miller\"\n2:0::30\n3:2::\"1234 Main St. Anytown, USA 12345\"\n";
        // Example valid input byte array
        byte[] validInput = Base64.getDecoder().decode(inputString);
        validInput = DecoderUtils.extractPayload(validInput);
        decoder.decode(validInput);
        assertEquals(expectedOutput, decoder.getDecodedOutput());
        assertEquals(3, decoder.getDecodedToList().size());
    }

    @Test
    void shouldDecodeWithNestedMessageValidInput() {
        String inputString =
                "AAAAAEEKEEhlbGxvLCBQcm90b2J1ZiESJwoESm9obhIGTWlsbGVyGhcKBEpvaG4QAhoNCgtIZWxsbyBXb3JsZBjqrcDlJA";
        String expectedOutput =
                "1:2::\"Hello, Protobuf!\"\n2:2N::{\n1:2::\"John\"\n2:2::\"Miller\"\n3:2N::{\n1:2::\"John\"\n2:0::2\n3:2N::{\n1:2::\"Hello World\"\n}\n}\n}\n3:0::9876543210\n";
        // Example valid input byte array
        byte[] validInput = Base64.getDecoder().decode(inputString);
        validInput = DecoderUtils.extractPayload(validInput);
        decoder.decode(validInput);
        assertEquals(expectedOutput, decoder.getDecodedOutput());
        assertEquals(3, decoder.getDecodedToList().size());
    }

    @Test
    void shouldDecodeWithEnumAndRepeatedFieldsInput() {
        // Example corrupted input byte array
        String inputString = "AAAAAA4IARIBYRIBYhIBYxIBZA";
        String expectedOutput = "1:0::1\n2:2::\"a\"\n2:2::\"b\"\n2:2::\"c\"\n2:2::\"d\"\n";
        byte[] validInput = Base64.getDecoder().decode(inputString);
        validInput = DecoderUtils.extractPayload(validInput);
        decoder.decode(validInput);
        assertEquals(expectedOutput, decoder.getDecodedOutput());
        assertEquals(5, decoder.getDecodedToList().size());
    }

    @Test
    void shouldDecodeWithDoubleAndFloatInput() {
        String inputString = "AAAAAA4JzczMzMzcXkAVrseHQg";
        String expectedOutput = "1:1D::123.45\n2:5F::67.89\n";
        byte[] validInput = Base64.getDecoder().decode(inputString);
        validInput = DecoderUtils.extractPayload(validInput);
        decoder.decode(validInput);
        assertEquals(expectedOutput, decoder.getDecodedOutput());
        assertEquals(2, decoder.getDecodedToList().size());
    }

    @Test
    void shouldDecodeWithWireType1And6Input() {
        String inputString = "AAAAAA4NQEIPABHMm5cAyicBAA";
        String expectedOutput = "1:5::1000000\n2:1::325223523523532\n";
        byte[] validInput = Base64.getDecoder().decode(inputString);
        validInput = DecoderUtils.extractPayload(validInput);
        decoder.decode(validInput);
        assertEquals(expectedOutput, decoder.getDecodedOutput());
        assertEquals(2, decoder.getDecodedToList().size());
    }

    @Test
    void shouldDecodeWithCorruptedInput() {
        mockMessages(new ExtensionGrpc());
        // Example corrupted input byte array
        String invalidString =
                "AAAAADEPC2pvaG4gTWlsbGVyEB4aIDEyMzQgTWFpbiBTdC4gQW55dG93biwgVVNBIDEyMzQ1";
        byte[] invalidInput = Base64.getDecoder().decode(invalidString);
        byte[] finalInvalidInput = DecoderUtils.extractPayload(invalidInput);
        IllegalArgumentException exception =
                assertThrows(
                        IllegalArgumentException.class, () -> decoder.decode(finalInvalidInput));

        String expectedExceptionMessage =
                "Failed to decode protobuf message: The message format is invalid or corrupted";
        assertEquals(expectedExceptionMessage, exception.getMessage());
        assertEquals(2, decoder.getDecodedToList().size());
    }
}
