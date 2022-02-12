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
package org.zaproxy.addon.network.internal.handlers;

import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.channel.Channel;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelOption;
import io.netty.channel.ChannelPipeline;
import io.netty.channel.SimpleChannelInboundHandler;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.net.SocketException;
import java.util.Objects;
import java.util.concurrent.LinkedBlockingQueue;
import org.zaproxy.addon.network.internal.ChannelAttributes;
import org.zaproxy.zap.PersistentConnectionListener;

/**
 * Handler that exposes a {@link Socket} for a given {@link Channel}.
 *
 * <p>Provides compatibility with legacy {@link PersistentConnectionListener}s used by ZAP core.
 */
public class LegacySocketAdapter extends SimpleChannelInboundHandler<ByteBuf> {

    static final String HANDLER_NAME = "legacy.socket";

    private final LinkedBlockingQueue<Integer> pendingReads;
    private final ByteBuf buf;

    private final Channel inboundChannel;
    private final InputStream inputStream;
    private final OutputStream outputStream;
    private final Socket socket;

    /**
     * Constructs a {@code LegacySocketAdapter} for the given channel.
     *
     * @param channel the channel from where to read/write.
     * @throws NullPointerException if the given channel is {@code null}.
     */
    public LegacySocketAdapter(Channel channel) {
        this.inboundChannel = Objects.requireNonNull(channel);

        this.pendingReads = new LinkedBlockingQueue<>();
        this.buf = Unpooled.buffer();

        inputStream = new InputStreamImpl();
        outputStream = new OutputStreamImpl();
        socket = new SocketImpl();

        ChannelPipeline pipeline = channel.pipeline();
        pipeline.remove("timeout");

        if (channel.attr(ChannelAttributes.TLS_UPGRADED).get()) {
            pipeline.addAfter(TlsProtocolHandler.TLS_HANDLER_NAME, HANDLER_NAME, this);
        } else {
            pipeline.addFirst(HANDLER_NAME, this);
        }
    }

    /**
     * Gets the {@code Socket} that exposes the channel.
     *
     * @return the socket, never {@code null}.
     */
    public Socket getSocket() {
        return socket;
    }

    @Override
    protected void channelRead0(ChannelHandlerContext ctx, ByteBuf msg) throws Exception {
        buf.writeBytes(msg);
        pendingReads.offer(1);
    }

    @Override
    public void channelInactive(ChannelHandlerContext ctx) throws Exception {
        pendingReads.offer(1);
    }

    private class SocketImpl extends Socket {

        @Override
        public InputStream getInputStream() throws IOException {
            return inputStream;
        }

        @Override
        public OutputStream getOutputStream() throws IOException {
            return outputStream;
        }

        @Override
        public boolean isClosed() {
            return !inboundChannel.isActive();
        }

        @Override
        public boolean isConnected() {
            return true;
        }

        @Override
        public void setKeepAlive(boolean on) throws SocketException {
            inboundChannel.config().setOption(ChannelOption.SO_KEEPALIVE, on);
        }

        @Override
        public void setTcpNoDelay(boolean on) throws SocketException {
            inboundChannel.config().setOption(ChannelOption.TCP_NODELAY, on);
        }
    }

    private class InputStreamImpl extends InputStream {

        @Override
        public int read() throws IOException {
            throw new IOException("Operation not supported");
        }

        @Override
        public int read(byte[] b, int off, int len) throws IOException {
            try {
                pendingReads.take();
                if (!inboundChannel.isActive()) {
                    buf.release();
                    return -1;
                }
                int read = Math.min(len, buf.readableBytes());
                buf.readBytes(b, off, read);
                while (!buf.isReadable() && pendingReads.poll() != null) ;
                return read;
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }

            return -1;
        }

        @Override
        public void close() throws IOException {
            inboundChannel.close().addListener(f -> pendingReads.offer(1));
        }
    }

    private class OutputStreamImpl extends OutputStream {

        @Override
        public void write(int b) throws IOException {
            throw new IOException("Operation not supported");
        }

        @Override
        public void write(byte[] b, int off, int len) throws IOException {
            inboundChannel.writeAndFlush(Unpooled.copiedBuffer(b, off, len));
        }

        @Override
        public void close() throws IOException {
            inboundChannel.close();
        }
    }
}
