package org.zaproxy.zap.extension.pscanrulesAlpha;

import org.junit.Test;

import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.Optional;

import static org.hamcrest.Matchers.equalTo;
import static org.junit.Assert.assertThat;
import static org.zaproxy.zap.extension.pscanrulesAlpha.Decoders.NULL_TERMINATED_STRING;
import static org.zaproxy.zap.extension.pscanrulesAlpha.Decoders.RGBA_COMPONENT;
import static org.zaproxy.zap.extension.pscanrulesAlpha.Decoders.STRING;
import static org.zaproxy.zap.extension.pscanrulesAlpha.Decoders.UNIT;
import static org.zaproxy.zap.extension.pscanrulesAlpha.Decoders.UNSIGNED_INT;
import static org.zaproxy.zap.extension.pscanrulesAlpha.Decoders.UUID;

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
                NULL_TERMINATED_STRING.decoder
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
                NULL_TERMINATED_STRING.decoder
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
                RGBA_COMPONENT.decoder
                        .apply(ByteBuffer.wrap(data))
                        .map(StringBuilder::toString);

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
}
