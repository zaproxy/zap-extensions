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
import java.net.InetSocketAddress;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.network.internal.ChannelAttributes;

/**
 * Sets common properties to the {@code HttpMessage}.
 *
 * <ul>
 *   <li>The sender address, obtained from the channel attribute {@link
 *       ChannelAttributes#REMOTE_ADDRESS}.
 * </ul>
 */
@Sharable
public class CommonMessagePropertiesHandler extends SimpleChannelInboundHandler<HttpMessage> {

    private static final CommonMessagePropertiesHandler INSTANCE =
            new CommonMessagePropertiesHandler();

    /**
     * Gets the instance of this handler.
     *
     * @return the instance, never {@code null}.
     */
    public static CommonMessagePropertiesHandler getInstance() {
        return INSTANCE;
    }

    @Override
    public boolean isSharable() {
        return true;
    }

    @Override
    public void channelRead0(ChannelHandlerContext ctx, HttpMessage msg) throws Exception {
        InetSocketAddress remoteAddress =
                ctx.channel().attr(ChannelAttributes.REMOTE_ADDRESS).get();
        if (remoteAddress != null) {
            msg.getRequestHeader().setSenderAddress(remoteAddress.getAddress());
        }

        ctx.fireChannelRead(msg);
    }
}
