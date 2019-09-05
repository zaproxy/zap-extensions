package org.zaproxy.zap.extension.pscanrulesAlpha;

import org.junit.Test;

import java.nio.ByteBuffer;
import java.util.Optional;

import static org.hamcrest.Matchers.equalTo;
import static org.junit.Assert.assertThat;
import static org.zaproxy.zap.extension.pscanrulesAlpha.Decoders.UNSIGNED_INT;

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
}
