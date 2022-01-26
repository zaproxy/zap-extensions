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

import io.netty.channel.ChannelHandler.Sharable;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.SimpleChannelInboundHandler;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpRequestHeader;

/**
 * Handles HTTTP CONNECT requests by inserting a {@link TlsProtocolHandler} in the pipeline with the
 * requested authority.
 *
 * <p>The handler removes itself after processing the HTTP message.
 *
 * @see #getInstance()
 */
@Sharable
public class ConnectRequestHandler extends SimpleChannelInboundHandler<HttpMessage> {

    private static final ConnectRequestHandler INSTANCE = new ConnectRequestHandler();

    /**
     * Gets the instance of this handler.
     *
     * @return the instance, never {@code null}.
     */
    public static ConnectRequestHandler getInstance() {
        return INSTANCE;
    }

    @Override
    public boolean isSharable() {
        return true;
    }

    @Override
    public void channelRead0(ChannelHandlerContext ctx, HttpMessage msg) throws Exception {
        if (msg.getUserObject() instanceof Exception) {
            throw (Exception) msg.getUserObject();
        }

        HttpRequestHeader request = msg.getRequestHeader();
        boolean connect = HttpRequestHeader.CONNECT.equals(request.getMethod());
        ctx.fireChannelRead(msg);
        ctx.pipeline().remove(this);

        if (!connect) {
            return;
        }

        ctx.pipeline().addFirst("tls.upgrade", new TlsProtocolHandler(request.getHostName()));
        ctx.fireChannelReadComplete();
    }
}
