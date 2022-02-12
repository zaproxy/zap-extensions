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
package org.zaproxy.addon.network.internal.server;

import io.netty.bootstrap.ServerBootstrap;
import io.netty.channel.Channel;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInitializer;
import io.netty.channel.group.ChannelGroup;
import io.netty.channel.group.DefaultChannelGroup;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.channel.socket.ServerSocketChannel;
import io.netty.channel.socket.SocketChannel;
import io.netty.channel.socket.nio.NioServerSocketChannel;
import io.netty.util.concurrent.GlobalEventExecutor;
import java.io.IOException;
import java.util.Objects;
import java.util.function.Consumer;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.zaproxy.addon.network.internal.ChannelAttributes;
import org.zaproxy.addon.network.internal.handlers.ChannelGroupHandler;
import org.zaproxy.addon.network.server.Server;

/**
 * The base server.
 *
 * <p>Provides basic functionality, allows to be started and stopped, and initialise the child
<<<<<<< HEAD
 * channels.
 *
 * <p>It also adds the following channel attributes:
 *
 * <ul>
 *   <li>{@link ChannelAttributes#LOCAL_ADDRESS};
 *   <li>{@link ChannelAttributes#REMOTE_ADDRESS};
 *   <li>{@link ChannelAttributes#TLS_UPGRADED} (always {@code false});
 *   <li>{@link ChannelAttributes#PROCESSING_MESSAGE} (always {@code false});
 *   <li>{@link ChannelAttributes#RECURSIVE_MESSAGE} (always {@code false}).
 * </ul>
=======
 * channels. It also adds the following channel attributes: {@link ChannelAttributes#LOCAL_ADDRESS},
 * {@link ChannelAttributes#REMOTE_ADDRESS}, and {@link ChannelAttributes#TLS_UPGRADED} (always
 * {@code false}).
>>>>>>> 6790cf8a44d6ba1358ac50cc1fefcb8d44445e10
 */
public class BaseServer implements Server {

    private static final Logger LOGGER = LogManager.getLogger(BaseServer.class);

    private final ServerBootstrap bootstrap;
<<<<<<< HEAD
    private Consumer<SocketChannel> channelInitialiser;
=======
    private final Consumer<SocketChannel> channelInitialiser;
>>>>>>> 6790cf8a44d6ba1358ac50cc1fefcb8d44445e10
    private ChannelGroup allChannels;
    private Channel serverChannel;

    /**
<<<<<<< HEAD
     * Constructs a {@code BaseServer} with the given event loop group and no channel initialiser.
     *
     * <p>The channel initialiser is expected to be set before starting the server, failing to do so
     * will result in an exception.
     *
     * @param group the event loop group.
     * @see #setChannelInitialiser(Consumer)
     */
    protected BaseServer(NioEventLoopGroup group) {
        Objects.requireNonNull(group);
=======
     * Constructs a {@code BaseServer} with the given event loop group and channel initialiser.
     *
     * @param group the event loop group.
     * @param channelInitialiser the channel initialiser.
     */
    public BaseServer(NioEventLoopGroup group, Consumer<SocketChannel> channelInitialiser) {
        Objects.requireNonNull(group);
        this.channelInitialiser = Objects.requireNonNull(channelInitialiser);
>>>>>>> 6790cf8a44d6ba1358ac50cc1fefcb8d44445e10

        this.bootstrap =
                new ServerBootstrap()
                        .group(group)
                        .channel(NioServerSocketChannel.class)
                        .childHandler(new ChannelInitializerImpl());
    }

<<<<<<< HEAD
    /**
     * Constructs a {@code BaseServer} with the given event loop group and channel initialiser.
     *
     * @param group the event loop group.
     * @param channelInitialiser the channel initialiser.
     * @throws NullPointerException if the given channel initialiser is {@code null}.
     */
    public BaseServer(NioEventLoopGroup group, Consumer<SocketChannel> channelInitialiser) {
        this(group);

        setChannelInitialiser(channelInitialiser);
    }

    /**
     * Sets the channel initialiser.
     *
     * @param channelInitialiser the channel initialiser.
     * @throws NullPointerException if the given channel initialiser is {@code null}.
     */
    protected void setChannelInitialiser(Consumer<SocketChannel> channelInitialiser) {
        this.channelInitialiser = Objects.requireNonNull(channelInitialiser);
    }

    /**
     * Tells whether or not the server is started.
     *
     * @return {@code true} if the server is started, {@code false} otherwise.
     */
    public boolean isStarted() {
        return serverChannel != null;
    }

=======
>>>>>>> 6790cf8a44d6ba1358ac50cc1fefcb8d44445e10
    @Override
    public int start(String address, int port) throws IOException {
        Server.validatePort(port);

<<<<<<< HEAD
        if (channelInitialiser == null) {
            throw new IOException("No channel initialiser set.");
        }

=======
>>>>>>> 6790cf8a44d6ba1358ac50cc1fefcb8d44445e10
        stop();

        allChannels = new DefaultChannelGroup(GlobalEventExecutor.INSTANCE, true);
        try {
            serverChannel = bootstrap.bind(address, port).sync().channel();
            allChannels.add(serverChannel);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IOException("Interrupted while waiting for the server to start.", e);
        } catch (IllegalArgumentException e) {
            throw e;
        } catch (Exception e) {
            if (e instanceof IOException) {
                throw e;
            }
            throw new IOException(e);
        }

        return ((ServerSocketChannel) serverChannel).localAddress().getPort();
    }

    /**
     * Gets all active channels of the server.
     *
     * @return the channel group containing all active channels.
     */
    protected ChannelGroup getAllChannels() {
        return allChannels;
    }

    @Override
    public void stop() throws IOException {
        if (serverChannel == null) {
            return;
        }

        try {
            allChannels.close().sync();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IOException("Interrupted while waiting for the server to stop.", e);
        } catch (Exception e) {
            if (e instanceof IOException) {
                throw e;
            }
            throw new IOException(e);
        } finally {
            serverChannel = null;
        }
    }

<<<<<<< HEAD
    @Override
    public void close() throws IOException {
        stop();
    }

=======
>>>>>>> 6790cf8a44d6ba1358ac50cc1fefcb8d44445e10
    private class ChannelInitializerImpl extends ChannelInitializer<SocketChannel> {

        @Override
        public void initChannel(SocketChannel ch) {
            ch.attr(ChannelAttributes.LOCAL_ADDRESS).set(ch.localAddress());
            ch.attr(ChannelAttributes.REMOTE_ADDRESS).set(ch.remoteAddress());
            ch.attr(ChannelAttributes.TLS_UPGRADED).set(Boolean.FALSE);
<<<<<<< HEAD
            ch.attr(ChannelAttributes.PROCESSING_MESSAGE).set(Boolean.FALSE);
            ch.attr(ChannelAttributes.RECURSIVE_MESSAGE).set(Boolean.FALSE);
=======
>>>>>>> 6790cf8a44d6ba1358ac50cc1fefcb8d44445e10

            ch.pipeline().addLast(new ChannelGroupHandler(allChannels));

            channelInitialiser.accept(ch);
        }

        @Override
        public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) throws Exception {
            LOGGER.error(
                    "An error occurred while initializing the channel. Closing: {}",
                    ctx.channel(),
                    cause);
            ctx.close();
        }
    }
}
