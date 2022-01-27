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
package org.zaproxy.addon.network.internal.codec;

import io.netty.buffer.ByteBuf;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.CombinedChannelDuplexHandler;
import java.util.ArrayDeque;
import java.util.List;
import java.util.Queue;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpRequestHeader;

/**
 * Encodes a HTTP request and decodes a HTTP response into a {@link HttpMessage}.
 *
 * <p>Based on Netty's {@code HttpClientCodec}.
 */
public class HttpClientCodec
        extends CombinedChannelDuplexHandler<HttpResponseDecoder, HttpRequestEncoder> {
    private final Queue<String> queue = new ArrayDeque<>();

    /** Constructs a {@code HttpClientCodec}. */
    public HttpClientCodec() {
        init(new Decoder(), new Encoder());
    }

    private class Encoder extends HttpRequestEncoder {

        @Override
        protected void encode(ChannelHandlerContext ctx, HttpMessage msg, ByteBuf out) {
            queue.offer(msg.getRequestHeader().getMethod());
            super.encode(ctx, msg, out);
        }
    }

    private class Decoder extends HttpResponseDecoder {

        @Override
        protected void decode(ChannelHandlerContext ctx, ByteBuf buffer, List<Object> out)
                throws Exception {
            super.decode(ctx, buffer, out);
        }

        @Override
        protected boolean isContentAlwaysEmpty(HttpMessage msg) {
            String method = queue.poll();

            int statusCode = msg.getResponseHeader().getStatusCode();
            if (statusCode >= 100 && statusCode < 200) {
                return super.isContentAlwaysEmpty(msg);
            }

            if (method != null) {
                char firstChar = method.charAt(0);
                switch (firstChar) {
                    case 'H':
                        if (HttpRequestHeader.HEAD.equals(method)) {
                            return true;
                        }
                        break;
                    case 'C':
                        if (statusCode == 200 && HttpRequestHeader.CONNECT.equals(method)) {
                            return true;
                        }
                        break;
                    default:
                        break;
                }
            }
            return super.isContentAlwaysEmpty(msg);
        }
    }
}
