/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2023 The ZAP Development Team
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
package org.zaproxy.addon.network.internal;

import com.aayushatharva.brotli4j.Brotli4jLoader;
import com.aayushatharva.brotli4j.decoder.Decoder;
import com.aayushatharva.brotli4j.decoder.DecoderJNI;
import com.aayushatharva.brotli4j.decoder.DirectDecompress;
import com.aayushatharva.brotli4j.encoder.Encoder;
import java.io.IOException;
import org.zaproxy.zap.network.HttpEncoding;

/** The {@link HttpEncoding} for the {@code br} coding. */
class HttpEncodingBrotli implements HttpEncoding {

    private static final HttpEncodingBrotli SINGLETON = new HttpEncodingBrotli();

    private static final boolean AVAILABLE;

    static {
        boolean available = false;
        try {
            Brotli4jLoader.ensureAvailability();
            available = true;
        } catch (UnsatisfiedLinkError e) {
            // Nothing to do.
        }
        AVAILABLE = available;
    }

    /**
     * Gets the singleton.
     *
     * @return the br content encoding.
     */
    public static HttpEncodingBrotli getSingleton() {
        return SINGLETON;
    }

    public static boolean isAvailable() {
        return AVAILABLE;
    }

    @Override
    public byte[] encode(byte[] content) throws IOException {
        return Encoder.compress(content);
    }

    @Override
    public byte[] decode(byte[] content) throws IOException {
        DirectDecompress directDecompress = Decoder.decompress(content);
        DecoderJNI.Status status = directDecompress.getResultStatus();
        if (status == DecoderJNI.Status.DONE) {
            return directDecompress.getDecompressedData();
        }
        throw new IOException("Failed to decode: " + status);
    }
}
