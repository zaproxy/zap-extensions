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
package org.zaproxy.addon.network.internal.server.http;

import io.netty.buffer.Unpooled;
import io.netty.channel.Channel;
import io.netty.channel.ChannelFuture;
import java.io.IOException;
import java.io.OutputStream;
import java.util.Objects;

/**
 * An {@code OutputStream} that writes the data, as it is written, to the channel as the body of a
 * response, after the response headers were written. The data is sent as is, any framing of the
 * data (for example, chunks) is up to the writer.
 *
 * <p>Closing the stream closes the channel, the connection state is up to the writer.
 */
class ResponseStream extends OutputStream {

    private final Channel channel;
    private boolean closed;

    ResponseStream(Channel channel) {
        this.channel = Objects.requireNonNull(channel);
    }

    boolean isClosed() {
        return closed;
    }

    @Override
    public void write(int b) throws IOException {
        write(new byte[] {(byte) b}, 0, 1);
    }

    @Override
    public void write(byte[] b, int off, int len) throws IOException {
        Objects.checkFromIndexSize(off, len, b.length);
        if (closed) {
            throw new IOException("The response stream was closed.");
        }
        if (len == 0) {
            return;
        }
        write(channel, Unpooled.wrappedBuffer(b, off, len));
    }

    @Override
    public void flush() {
        // Each write is flushed.
    }

    /** Closes the channel, and with it the connection. */
    @Override
    public void close() {
        if (closed) {
            return;
        }
        closed = true;
        channel.close();
    }

    /** Writes and flushes the given object, waiting for the write to complete. */
    static void write(Channel channel, Object msg) throws IOException {
        ChannelFuture future;
        try {
            future = channel.writeAndFlush(msg).await();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IOException("Interrupted while writing to the connection.", e);
        }
        if (!future.isSuccess()) {
            throw new IOException("Failed to write to the connection.", future.cause());
        }
    }
}
