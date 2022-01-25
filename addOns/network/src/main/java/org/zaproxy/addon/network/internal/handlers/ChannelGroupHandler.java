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

import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInboundHandlerAdapter;
import io.netty.channel.group.ChannelGroup;
import java.util.Objects;

/**
 * A handler that adds an activated channel to a {@link ChannelGroup}.
 *
 * <p>The handler removes itself after adding the channel.
 */
public class ChannelGroupHandler extends ChannelInboundHandlerAdapter {

    private final ChannelGroup channelGroup;

    /**
     * Constructs a {@code ChannelGroupHandler} with the given channel group.
     *
     * @param channelGroup the channel group to where to add the activated channels.
     * @throws NullPointerException if the given {@code channelGroup} is {@code null}.
     */
    public ChannelGroupHandler(ChannelGroup channelGroup) {
        this.channelGroup = Objects.requireNonNull(channelGroup);
    }

    @Override
    public void channelActive(ChannelHandlerContext ctx) throws Exception {
        channelGroup.add(ctx.channel());
        super.channelActive(ctx);
        ctx.pipeline().remove(ctx.name());
    }
}
