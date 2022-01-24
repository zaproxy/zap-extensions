/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2021 The ZAP Development Team
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

import java.net.InetSocketAddress;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpRequestHeader;
import org.zaproxy.addon.network.internal.ChannelAttributes;

/** Decodes HTTP request into a {@link HttpMessage}. */
public class HttpRequestDecoder extends HttpMessageDecoder {

    /** Constructs a {@code HttpRequestDecoder}. */
    public HttpRequestDecoder() {
        super(
                true,
                (ctx, msg, content) -> {
                    HttpRequestHeader header = msg.getRequestHeader();
                    boolean secure = ctx.channel().attr(ChannelAttributes.TLS_UPGRADED).get();
                    header.setMessage(content, secure);
                    InetSocketAddress remoteAddress =
                            ctx.channel().attr(ChannelAttributes.REMOTE_ADDRESS).get();
                    header.setSenderAddress(remoteAddress.getAddress());
                    return header;
                },
                HttpMessage::getRequestBody);
    }
}
