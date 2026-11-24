/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2022 The ZAP Development Team
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
package org.zaproxy.addon.network.server;

import java.io.FilterOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.Objects;

/**
 * An {@code OutputStream} that writes the data as the chunks of a chunked response ({@code
 * Transfer-Encoding: chunked}) to the wrapped stream, for example the stream of {@link
 * HttpMessageHandlerContext#streamingResponse(org.parosproxy.paros.network.HttpMessage)}.
 *
 * <p>Each write is sent as a chunk, closing the stream sends the last chunk and closes the wrapped
 * stream. The response header has to have {@code Transfer-Encoding: chunked}, it is not changed by
 * this class.
 *
 * @since 0.34.0
 */
public class ChunkedOutputStream extends FilterOutputStream {

    private static final byte[] CRLF = "\r\n".getBytes(StandardCharsets.US_ASCII);
    private static final byte[] LAST_CHUNK = "0\r\n\r\n".getBytes(StandardCharsets.US_ASCII);

    private boolean closed;

    /**
     * Constructs a stream that writes chunks to the given stream.
     *
     * @param out the stream to write the chunks to.
     * @throws NullPointerException if the given stream is {@code null}.
     */
    public ChunkedOutputStream(OutputStream out) {
        super(Objects.requireNonNull(out));
    }

    @Override
    public void write(int b) throws IOException {
        write(new byte[] {(byte) b}, 0, 1);
    }

    @Override
    public void write(byte[] b, int off, int len) throws IOException {
        Objects.checkFromIndexSize(off, len, b.length);
        if (closed) {
            throw new IOException("The stream was closed.");
        }
        if (len == 0) {
            // A chunk with no data would end the body.
            return;
        }
        byte[] size = Integer.toHexString(len).getBytes(StandardCharsets.US_ASCII);
        byte[] chunk = new byte[size.length + CRLF.length + len + CRLF.length];
        int pos = 0;
        System.arraycopy(size, 0, chunk, pos, size.length);
        pos += size.length;
        System.arraycopy(CRLF, 0, chunk, pos, CRLF.length);
        pos += CRLF.length;
        System.arraycopy(b, off, chunk, pos, len);
        pos += len;
        System.arraycopy(CRLF, 0, chunk, pos, CRLF.length);
        // As a single write, to be sent as a single chunk.
        out.write(chunk);
    }

    /**
     * Sends the last chunk and closes the wrapped stream, which is closed even if the last chunk
     * could not be written.
     *
     * @throws IOException if an error occurred while writing the last chunk.
     */
    @Override
    public void close() throws IOException {
        if (closed) {
            return;
        }
        closed = true;
        try {
            out.write(LAST_CHUNK);
        } finally {
            out.close();
        }
    }
}
