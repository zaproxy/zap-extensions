/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2019 The ZAP Development Team
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
package org.zaproxy.zap.extension.pscanrulesAlpha.viewState;

import org.junit.Test;

import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.Optional;

import static org.hamcrest.Matchers.equalTo;
import static org.junit.Assert.assertThat;
import static org.zaproxy.zap.extension.pscanrulesAlpha.viewState.Decoders.ARRAY_OF_STRING;
import static org.zaproxy.zap.extension.pscanrulesAlpha.viewState.Decoders.CONTAINERS_OF_BOOLEANS;
import static org.zaproxy.zap.extension.pscanrulesAlpha.viewState.Decoders.CONTAINER_OF_OBJECTS;
import static org.zaproxy.zap.extension.pscanrulesAlpha.viewState.Decoders.CONTROL_STATE;
import static org.zaproxy.zap.extension.pscanrulesAlpha.viewState.Decoders.NULL_TERMINATED_STRING;
import static org.zaproxy.zap.extension.pscanrulesAlpha.viewState.Decoders.RGBA_COMPONENT;
import static org.zaproxy.zap.extension.pscanrulesAlpha.viewState.Decoders.STRING;
import static org.zaproxy.zap.extension.pscanrulesAlpha.viewState.Decoders.STRING_REFERENCE;
import static org.zaproxy.zap.extension.pscanrulesAlpha.viewState.Decoders.TRIPLE;
import static org.zaproxy.zap.extension.pscanrulesAlpha.viewState.Decoders.TUPLE;
import static org.zaproxy.zap.extension.pscanrulesAlpha.viewState.Decoders.UNIT;
import static org.zaproxy.zap.extension.pscanrulesAlpha.viewState.Decoders.UNSIGNED_INT;
import static org.zaproxy.zap.extension.pscanrulesAlpha.viewState.Decoders.UUID;

public class DecodersTest {
    @Test
    public void shouldDecodeAnUnsignedInt() {
        // Given
        byte[] data = new byte[] {(byte) (94 + 0x80), (byte) 0x00};

        // When
        Optional<String> content =
                UNSIGNED_INT.decoder.apply(ByteBuffer.wrap(data)).map(StringBuilder::toString);

        // Then
        assertThat(content, equalTo(Optional.of("<uint32>94</uint32>")));
    }

    @Test
    public void shouldDecodeNullTerminatedString() {
        // Given
        byte[] data = new byte[] {'t', 'e', 's', 't', 0x00};

        // When
        Optional<String> content =
                NULL_TERMINATED_STRING
                        .decoder
                        .apply(ByteBuffer.wrap(data))
                        .map(StringBuilder::toString);

        // Then
        assertThat(
                content, equalTo(Optional.of("<stringnullterminated>test</stringnullterminated>")));
    }

    @Test
    public void shouldDecodeMaliciousNullTerminatedString() {
        // Given
        byte[] data = new byte[] {'&', 0x00};

        // When
        Optional<String> content =
                NULL_TERMINATED_STRING
                        .decoder
                        .apply(ByteBuffer.wrap(data))
                        .map(StringBuilder::toString);

        // Then
        assertThat(
                content,
                equalTo(Optional.of("<stringnullterminated><![CDATA[&]]></stringnullterminated>")));
    }

    @Test
    public void shouldDecodeString() {
        // Given
        byte[] data = new byte[] {0x04, 't', 'e', 's', 't'};

        // When
        Optional<String> content =
                STRING.decoder.apply(ByteBuffer.wrap(data)).map(StringBuilder::toString);

        // Then
        assertThat(content, equalTo(Optional.of("<string>test</string>")));
    }

    @Test
    public void shouldDecodeMaliciousString() {
        // Given
        byte[] data = new byte[] {0x01, '&'};

        // When
        Optional<String> content =
                STRING.decoder.apply(ByteBuffer.wrap(data)).map(StringBuilder::toString);

        // Then
        assertThat(content, equalTo(Optional.of("<string><![CDATA[&]]></string>")));
    }

    @Test
    public void shouldDecodeAnUuid() {
        // Given
        byte[] data = new byte[36];
        Arrays.fill(data, (byte) 0xDE);

        // When
        Optional<String> content =
                UUID.decoder.apply(ByteBuffer.wrap(data)).map(StringBuilder::toString);

        // Then
        assertThat(
                content,
                equalTo(
                        Optional.of(
                                "<uuid>0xdededededededededededededededededededededededededededededededededededede</uuid>")));
    }

    @Test
    public void shouldDecodeRgbaComponent() {
        // Given
        byte[] data =
                new byte[] {
                    (byte) 0xDE, (byte) 0xAD, (byte) 0xBE, (byte) 0xEF,
                };

        // When
        Optional<String> content =
                RGBA_COMPONENT.decoder.apply(ByteBuffer.wrap(data)).map(StringBuilder::toString);

        // Then
        assertThat(content, equalTo(Optional.of("<rgba>0xdeadbeef</rgba>")));
    }

    @Test
    public void shouldDecodeUnit() {
        // Given
        byte[] data =
                new byte[] {
                    (byte) 0xDE, (byte) 0xAD, (byte) 0xBE, (byte) 0xEF,
                    (byte) 0xDE, (byte) 0xAD, (byte) 0xBE, (byte) 0xEF,
                    (byte) 0xDE, (byte) 0xAD, (byte) 0xBE, (byte) 0xEF,
                };

        // When
        Optional<String> content =
                UNIT.decoder.apply(ByteBuffer.wrap(data)).map(StringBuilder::toString);

        // Then
        assertThat(content, equalTo(Optional.of("<unit>0xdeadbeefdeadbeefdeadbeef</unit>")));
    }

    @Test
    public void shouldDecodeStringReference() {
        // Given
        byte[] data = new byte[] {(byte) 0xDE, (byte) 0xAD, (byte) 0xBE, (byte) 0xEF, 0x00};

        // When
        Optional<String> content =
                STRING_REFERENCE.decoder.apply(ByteBuffer.wrap(data)).map(StringBuilder::toString);

        // Then
        assertThat(content, equalTo(Optional.of("<stringreference>233805534</stringreference>")));
    }

    @Test
    public void shouldDecodeContainerOfBooleans() {
        // Given
        byte[] data =
                new byte[] {
                    0x02, // Size
                    0x67, // type of boolean true
                    0x68, // type of boolean false
                };

        // When
        Optional<String> content =
                CONTAINERS_OF_BOOLEANS
                        .decoder
                        .apply(ByteBuffer.wrap(data))
                        .map(StringBuilder::toString);

        // Then
        assertThat(
                content,
                equalTo(
                        Optional.of(
                                "<booleanarray size=\"2\">"
                                        + "<boolean>true</boolean>"
                                        + "<boolean>false</boolean>"
                                        + "</booleanarray>")));
    }

    @Test
    public void shouldRejectAnInvalidEncodedContainerOfBooleans() {
        // Given
        byte[] data =
                new byte[] {
                    0x01, // Size
                    0x31, // Non-existing type
                };

        // When
        Optional<String> content =
                CONTAINERS_OF_BOOLEANS
                        .decoder
                        .apply(ByteBuffer.wrap(data))
                        .map(StringBuilder::toString);

        // Then
        assertThat(content, equalTo(Optional.empty()));
    }

    @Test
    public void shouldDecodeAContainerOfObjects() {
        byte[] data =
                new byte[] {
                    0x02, // Size
                    0x15, // Array of string
                    0x01, // Size of array of string
                    0x04, // Length of first string
                    't',
                    'e',
                    's',
                    't',
                    0x67 // boolean
                };

        // When
        Optional<String> content =
                CONTAINER_OF_OBJECTS
                        .decoder
                        .apply(ByteBuffer.wrap(data))
                        .map(StringBuilder::toString);

        // Then
        assertThat(
                content,
                equalTo(
                        Optional.of(
                                "<objectarray size=\"2\">"
                                        + "<stringarray size=\"1\">"
                                        + "<stringwithlength length=\"4\">test</stringwithlength>"
                                        + "</stringarray><boolean>true</boolean>"
                                        + "</objectarray>")));
    }

    @Test
    public void shouldRejectInvalidEncodedContainerOfObjects() {
        byte[] data = new byte[] {0x37};

        // When
        Optional<String> content =
                CONTAINER_OF_OBJECTS
                        .decoder
                        .apply(ByteBuffer.wrap(data))
                        .map(StringBuilder::toString);

        // Then
        assertThat(content, equalTo(Optional.empty()));
    }

    @Test
    public void shouldDecodeAnArrayOfString() {
        // Given
        byte[] data =
                new byte[] {
                    0x02, // Size
                    0x04, // Length of first string
                    't', 'e', 's', 't', 0x01, // Length of second string
                    '&'
                };

        // When
        Optional<String> content =
                ARRAY_OF_STRING.decoder.apply(ByteBuffer.wrap(data)).map(StringBuilder::toString);

        // Then
        assertThat(
                content,
                equalTo(
                        Optional.of(
                                "<stringarray size=\"2\">"
                                        + "<stringwithlength length=\"4\">test</stringwithlength>"
                                        + "<stringwithlength length=\"1\"><![CDATA[&]]></stringwithlength>"
                                        + "</stringarray>")));
    }

    @Test
    public void shouldDecodeAnControlState() {
        // Given
        byte[] data =
                new byte[] {
                    0x02, // Size
                    0x05, // type String
                    0x04, // Length of first string
                    't', 'e', 's', 't', 0x05, // type String
                    0x01, // Length of second string
                    '&'
                };

        // When
        Optional<String> content =
                CONTROL_STATE.decoder.apply(ByteBuffer.wrap(data)).map(StringBuilder::toString);

        // Then
        assertThat(
                content,
                equalTo(
                        Optional.of(
                                "<controlstate size=\"2\">"
                                        + "<string>test</string>"
                                        + "<string><![CDATA[&]]></string>"
                                        + "</controlstate>")));
    }

    @Test
    public void shouldRejectAnInvalidEncodedControlState() {
        // Given
        byte[] data =
                new byte[] {
                    0x02, // Size
                    0x31, // Invalid type
                };

        // When
        Optional<String> content =
                CONTROL_STATE.decoder.apply(ByteBuffer.wrap(data)).map(StringBuilder::toString);

        // Then
        assertThat(content, equalTo(Optional.empty()));
    }

    @Test
    public void shouldDecodeTriple() {
        // Given
        byte[] data = new byte[] {0x67, 0x68, 0x67};

        // When
        Optional<String> content =
                TRIPLE.decoder.apply(ByteBuffer.wrap(data)).map(StringBuilder::toString);

        // Then
        assertThat(
                content,
                equalTo(
                        Optional.of(
                                "<triple>"
                                        + "<boolean>true</boolean>"
                                        + "<boolean>false</boolean>"
                                        + "<boolean>true</boolean>"
                                        + "</triple>")));
    }

    @Test
    public void shouldRejectInvalidEncodedTriple() {
        // Given
        byte[] data = new byte[] {0x31};

        // When
        Optional<String> content =
                TRIPLE.decoder.apply(ByteBuffer.wrap(data)).map(StringBuilder::toString);

        // Then
        assertThat(content, equalTo(Optional.empty()));
    }

    @Test
    public void shouldDecodeTuple() {
        // Given
        byte[] data = new byte[] {0x67, 0x68};

        // When
        Optional<String> content =
                TUPLE.decoder.apply(ByteBuffer.wrap(data)).map(StringBuilder::toString);

        // Then
        assertThat(
                content,
                equalTo(
                        Optional.of(
                                "<pair>"
                                        + "<boolean>true</boolean>"
                                        + "<boolean>false</boolean>"
                                        + "</pair>")));
    }

    @Test
    public void shouldRejectInvalidEncodedTuple() {
        // Given
        byte[] data = new byte[] {0x31};

        // When
        Optional<String> content =
                TUPLE.decoder.apply(ByteBuffer.wrap(data)).map(StringBuilder::toString);

        // Then
        assertThat(content, equalTo(Optional.empty()));
    }
}
