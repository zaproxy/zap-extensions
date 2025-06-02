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
package org.zaproxy.addon.network.testutils;

import io.netty.bootstrap.Bootstrap;
import io.netty.buffer.Unpooled;
import io.netty.channel.Channel;
import io.netty.channel.ChannelFutureListener;
import io.netty.channel.ChannelInitializer;
import io.netty.channel.ChannelOption;
import io.netty.channel.EventLoopGroup;
import io.netty.channel.group.ChannelGroup;
import io.netty.channel.group.DefaultChannelGroup;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.channel.socket.SocketChannel;
import io.netty.channel.socket.nio.NioSocketChannel;
import io.netty.util.NettyRuntime;
import io.netty.util.concurrent.DefaultThreadFactory;
import io.netty.util.concurrent.GlobalEventExecutor;
import java.io.Closeable;
import java.io.IOException;
import java.util.function.Consumer;
import org.zaproxy.addon.network.internal.handlers.ChannelGroupHandler;

/** A simple client to help with the tests. */
public class TestClient implements Closeable {

    private final String address;
    private final Consumer<SocketChannel> channelInitialiser;
    private final ChannelGroup allChannels;
    private final EventLoopGroup group;
    private final Bootstrap bootstrap;

    /**
     * Constructs a {@code TestClient} with the given address and channel initialiser.
     *
     * @param address the address to connect to.
     * @param channelInitialiser the channel initialiser.
     */
    public TestClient(String address, Consumer<SocketChannel> channelInitialiser) {
        this.address = address;
        this.channelInitialiser = channelInitialiser;

        allChannels = new DefaultChannelGroup(GlobalEventExecutor.INSTANCE);
        group =
                new NioEventLoopGroup(
                        NettyRuntime.availableProcessors(),
                        new DefaultThreadFactory("ZAP-TestClient"));
        bootstrap =
                new Bootstrap()
                        .group(group)
                        .channel(NioSocketChannel.class)
                        .option(ChannelOption.CONNECT_TIMEOUT_MILLIS, 1000)
                        .handler(new ChannelInitializerImpl());
    }

    /**
     * Gets the count of channels.
     *
     * @return the count of channels.
     */
    public int getChannelsCount() {
        return allChannels.size();
    }

    /**
     * Sends the message to the given port.
     *
     * <p>The message is sent synchronously and the connection is closed.
     *
     * @param port the port to where to connect.
     * @param msg the message, can be {@code null}.
     * @throws Exception if an error occurred while sending the message.
     */
    public <T> void send(int port, T msg) throws Exception {
        connect(port, msg)
                .writeAndFlush(Unpooled.EMPTY_BUFFER)
                .addListener(ChannelFutureListener.CLOSE)
                .sync();
    }

    /**
     * Connects and sends the message to the given port.
     *
     * <p>The message is sent synchronously.
     *
     * @param port the port to where to connect.
     * @param msg the message, can be {@code null}.
     * @return the channel, possibly connected to the given port.
     * @throws Exception if an error occurred while sending the message.
     */
    public <T> Channel connect(int port, T msg) throws Exception {
        Channel channel = bootstrap.connect(address, port).sync().channel();
        if (msg != null) {
            channel.writeAndFlush(msg).sync();
        }
        return channel;
    }

    /**
     * Closes all channels.
     *
     * @throws Exception if an error occurred while closing the channels.
     */
    public void closeChannels() throws Exception {
        allChannels.close().sync();
    }

    /**
     * Waits until all channels are closed.
     *
     * @throws InterruptedException if interrupted while waiting for the channels to be closed.
     */
    public void waitChannelsClosed() throws InterruptedException {
        while (!allChannels.isEmpty()) {
            Thread.sleep(150);
        }
    }

    @Override
    public void close() throws IOException {
        try {
            closeChannels();
        } catch (Exception e) {
            throw new IOException(e);
        }
        group.shutdownGracefully();
    }

    private class ChannelInitializerImpl extends ChannelInitializer<SocketChannel> {

        @Override
        public void initChannel(SocketChannel ch) throws Exception {
            ch.pipeline().addLast(new ChannelGroupHandler(allChannels));

            channelInitialiser.accept(ch);
        }
    }
}
