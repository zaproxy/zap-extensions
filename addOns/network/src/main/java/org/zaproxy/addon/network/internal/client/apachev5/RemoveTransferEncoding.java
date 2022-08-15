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
package org.zaproxy.addon.network.internal.client.apachev5;

import org.apache.hc.client5.http.protocol.HttpClientContext;
import org.apache.hc.core5.http.EntityDetails;
import org.apache.hc.core5.http.HttpHeaders;
import org.apache.hc.core5.http.HttpResponse;
import org.apache.hc.core5.http.HttpResponseInterceptor;
import org.apache.hc.core5.http.protocol.HttpContext;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * A {@link HttpResponseInterceptor} that removes the Transfer-Encoding header, the response body is
 * read without preserving the chunks.
 */
public class RemoveTransferEncoding implements HttpResponseInterceptor {

    static final String ATTR_NAME = "zap.transfer-encoding.removed";

    private static final Logger LOGGER = LogManager.getLogger(RemoveTransferEncoding.class);

    @Override
    public void process(HttpResponse response, EntityDetails entity, HttpContext context) {
        if (response.removeHeaders(HttpHeaders.TRANSFER_ENCODING)) {
            context.setAttribute(ATTR_NAME, Boolean.TRUE);
            if (LOGGER.isDebugEnabled()) {
                HttpClientContext clientContext = HttpClientContext.adapt(context);
                LOGGER.debug(
                        "{} removing {} header",
                        clientContext.getExchangeId(),
                        HttpHeaders.TRANSFER_ENCODING);
            }
        }
    }
}
