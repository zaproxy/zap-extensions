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

import io.netty.channel.Channel;
import io.netty.channel.ChannelHandler.Sharable;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.SimpleChannelInboundHandler;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.util.Arrays;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.ice4j.TransportAddress;
import org.ice4j.ice.harvest.AwsCandidateHarvester;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpRequestHeader;
import org.zaproxy.addon.network.internal.ChannelAttributes;
import org.zaproxy.addon.network.internal.server.ServerConfig;

/**
 * A handler that checks if a HTTP request is a request to the server itself, thus recursive if
 * forwarded.
 *
 * <p>Sets the attribute {@link ChannelAttributes#RECURSIVE_MESSAGE} accordingly.
 *
 * @see #getInstance()
 */
@Sharable
public class RecursiveRequestHandler extends SimpleChannelInboundHandler<HttpMessage> {

    private static final Logger LOGGER = LogManager.getLogger(RecursiveRequestHandler.class);

    private static final RecursiveRequestHandler INSTANCE = new RecursiveRequestHandler();

    /**
     * Gets the instance of this handler.
     *
     * @return the instance, never {@code null}.
     */
    public static RecursiveRequestHandler getInstance() {
        return INSTANCE;
    }

    /**
     * Used to obtain the public address of an AWS EC2 instance.
     *
     * <p>Lazily initialised.
     *
     * @see #getAwsCandidateHarvester()
     * @see #isOwnPublicAddress(ServerConfig, InetAddress)
     */
    private static AwsCandidateHarvester awsCandidateHarvester;

    @Override
    public boolean isSharable() {
        return true;
    }

    @Override
    public void channelRead0(ChannelHandlerContext ctx, HttpMessage msg) throws Exception {
        if (msg.getUserObject() instanceof Exception) {
            throw (Exception) msg.getUserObject();
        }

        Channel channel = ctx.channel();
        boolean recursive = false;
        if (!HttpRequestHeader.CONNECT.equals(msg.getRequestHeader().getMethod())) {
            ServerConfig serverConfig = channel.attr(ChannelAttributes.SERVER_CONFIG).get();
            InetSocketAddress localInetAddress =
                    channel.attr(ChannelAttributes.LOCAL_ADDRESS).get();
            recursive = isRecursive(serverConfig, localInetAddress, msg.getRequestHeader());
        }
        channel.attr(ChannelAttributes.RECURSIVE_MESSAGE).set(recursive);

        ctx.fireChannelRead(msg);
    }

    /**
     * Tells whether or not the given {@code header} has a request to the server itself.
     *
     * <p>The request is to the server itself if one of the following conditions are met:
     *
     * <ol>
     *   <li>The requested domain is one of the server aliases, regardless of the port.
     *   <li>The requested address and port are the ones that the server is bound to.
     * </ol>
     *
     * @param serverConfig the server configuration.
     * @param localInetAddress the address of the server.
     * @param header the request that will be checked.
     * @return {@code true} if it is a request to the server itself, {@code false} otherwise.
     * @see #isProxyAddress(InetAddress)
     */
    private static boolean isRecursive(
            ServerConfig serverConfig,
            InetSocketAddress localInetAddress,
            HttpRequestHeader header) {
        try {
            if (serverConfig.isAlias(header)) {
                return true;
            }

            if (header.getHostPort() == localInetAddress.getPort()
                    && isServerAddress(
                            InetAddress.getByName(header.getHostName()),
                            serverConfig,
                            localInetAddress.getAddress())) {
                return true;
            }
        } catch (Exception e) {
            LOGGER.warn(e.getMessage(), e);
        }
        return false;
    }

    /**
     * Tells whether or not the given {@code address} is one of address(es) the server is bound to.
     *
     * <p>If the server is bound to any address it checks whether the given {@code address} is a
     * local address or if it belongs to a network interface. If not bound to any address, it checks
     * if it's the one it is bound to.
     *
     * @param address the address that will be checked.
     * @param serverConfig the server configuration.
     * @param serverAddress the address of the server.
     * @return {@code true} if it is one of the addresses the srever is bound to, {@code false}
     *     otherwise.
     * @see #isLocalAddress(InetAddress)
     * @see #isNetworkInterfaceAddress(InetAddress)
     */
    private static boolean isServerAddress(
            InetAddress address, ServerConfig serverConfig, InetAddress serverAddress) {
        if (serverConfig.isAnyLocalAddress()) {
            if (isLocalAddress(address)
                    || isNetworkInterfaceAddress(address)
                    || isOwnPublicAddress(serverConfig, address)) {
                return true;
            }
        } else if (address.equals(serverAddress)) {
            return true;
        }
        return false;
    }

    /**
     * Tells whether or not the given {@code address} is a loopback, a site local, or any local
     * address.
     *
     * @param address the address that will be checked
     * @return {@code true} if the address is loopback, site local, or any local address, {@code
     *     false} otherwise.
     * @see InetAddress#isLoopbackAddress()
     * @see InetAddress#isSiteLocalAddress()
     * @see InetAddress#isAnyLocalAddress()
     */
    private static boolean isLocalAddress(InetAddress address) {
        return address.isLoopbackAddress()
                || address.isSiteLocalAddress()
                || address.isAnyLocalAddress();
    }

    /**
     * Tells whether or not the given {@code address} belongs to any of the network interfaces.
     *
     * @param address the address that will be checked.
     * @return {@code true} if the address belongs to any of the network interfaces, {@code false}
     *     otherwise.
     * @see NetworkInterface#getByInetAddress(InetAddress)
     */
    private static boolean isNetworkInterfaceAddress(InetAddress address) {
        try {
            if (NetworkInterface.getByInetAddress(address) != null) {
                return true;
            }
        } catch (SocketException e) {
            LOGGER.warn("Failed to check if an address is from a network interface:", e);
        }
        return false;
    }

    /**
     * Tells whether or not the given {@code address} is a public address of the host, when behind
     * NAT.
     *
     * <p>Returns {@code false} if the server is not behind NAT.
     *
     * <p><strong>Implementation Note:</strong> Only AWS EC2 NAT detection is supported, by
     * requesting the public IP address from <a href=
     * "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/using-instance-addressing.html#working-with-ip-addresses">
     * AWS EC2 instance's metadata</a>.
     *
     * @param serverConfig the server configuration.
     * @param address the address that will be checked.
     * @return {@code true} if the address is public address of the host, {@code false} otherwise.
     * @see ServerConfig#isBehindNat()
     */
    private static boolean isOwnPublicAddress(ServerConfig serverConfig, InetAddress address) {
        if (!serverConfig.isBehindNat()) {
            return false;
        }

        // Support just AWS for now.
        TransportAddress publicAddress = getAwsCandidateHarvester().getMask();
        if (publicAddress == null) {
            return false;
        }
        return Arrays.equals(address.getAddress(), publicAddress.getAddress().getAddress());
    }

    private static AwsCandidateHarvester getAwsCandidateHarvester() {
        if (awsCandidateHarvester == null) {
            createAwsCandidateHarvester();
        }
        return awsCandidateHarvester;
    }

    private static synchronized void createAwsCandidateHarvester() {
        if (awsCandidateHarvester == null) {
            awsCandidateHarvester = new AwsCandidateHarvester();
        }
    }
}
