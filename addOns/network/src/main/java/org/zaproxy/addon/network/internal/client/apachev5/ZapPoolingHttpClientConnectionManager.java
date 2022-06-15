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

import org.apache.hc.client5.http.impl.io.ManagedHttpClientConnectionFactory;
import org.apache.hc.client5.http.impl.io.PoolingHttpClientConnectionManager;
import org.apache.hc.client5.http.impl.io.ZapHttpClientConnectionOperator;
import org.apache.hc.client5.http.socket.ConnectionSocketFactory;
import org.apache.hc.client5.http.socket.LayeredConnectionSocketFactory;
import org.apache.hc.client5.http.socket.PlainConnectionSocketFactory;
import org.apache.hc.core5.http.URIScheme;
import org.apache.hc.core5.http.config.RegistryBuilder;
import org.apache.hc.core5.pool.PoolConcurrencyPolicy;
import org.apache.hc.core5.pool.PoolReusePolicy;

/** A {@link PoolingHttpClientConnectionManager} with custom configuration. */
public class ZapPoolingHttpClientConnectionManager extends PoolingHttpClientConnectionManager {

    public ZapPoolingHttpClientConnectionManager(
            LayeredConnectionSocketFactory sslSocketFactory,
            ManagedHttpClientConnectionFactory connectionFactory) {
        super(
                new ZapHttpClientConnectionOperator(
                        RegistryBuilder.<ConnectionSocketFactory>create()
                                .register(
                                        URIScheme.HTTP.id,
                                        PlainConnectionSocketFactory.getSocketFactory())
                                .register(URIScheme.HTTPS.id, sslSocketFactory)
                                .build(),
                        null,
                        null),
                PoolConcurrencyPolicy.LAX,
                PoolReusePolicy.LIFO,
                null,
                connectionFactory);

        setDefaultMaxPerRoute(100);
        setMaxTotal(getDefaultMaxPerRoute() * 100);
    }
}
