/*
 * ====================================================================
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 * ====================================================================
 *
 * This software consists of voluntary contributions made by many
 * individuals on behalf of the Apache Software Foundation.  For more
 * information on the Apache Software Foundation, please see
 * <http://www.apache.org/>.
 *
 */

package org.apache.hc.core5.http2.impl;

import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

import org.apache.hc.core5.http.Header;
import org.apache.hc.core5.http.HttpException;
import org.apache.hc.core5.http.HttpRequest;
import org.apache.hc.core5.http.HttpVersion;
import org.apache.hc.core5.http.Method;
import org.apache.hc.core5.http.ProtocolException;
import org.apache.hc.core5.http.message.BasicHeader;
import org.apache.hc.core5.http.message.BasicHttpRequest;
import org.apache.hc.core5.http2.H2MessageConverter;
import org.apache.hc.core5.http2.H2PseudoRequestHeaders;
import org.apache.hc.core5.net.URIAuthority;

/**
 * HTTP/2 request converter, that does not validate the fields.
 */
public final class DefaultH2RequestConverter implements H2MessageConverter<HttpRequest> {

    public final static DefaultH2RequestConverter INSTANCE = new DefaultH2RequestConverter();

    @Override
    public HttpRequest convert(final List<Header> headers) throws HttpException {
        String method = null;
        String scheme = null;
        String authority = null;
        String path = null;
        final List<Header> messageHeaders = new ArrayList<>();

        for (int i = 0; i < headers.size(); i++) {
            final Header header = headers.get(i);
            final String name = header.getName();
            final String value = header.getValue();

            if (name.startsWith(":")) {
                switch (name) {
                    case H2PseudoRequestHeaders.METHOD:
                        if (method == null) {
                            method = value;
                        }
                        break;
                    case H2PseudoRequestHeaders.SCHEME:
                        if (scheme == null) {
                            scheme = value;
                        }
                        break;
                    case H2PseudoRequestHeaders.PATH:
                        if (path == null) {
                            path = value;
                        }
                        break;
                    case H2PseudoRequestHeaders.AUTHORITY:
                        if (authority == null) {
                            authority = value;
                        }
                        break;
                    default:
                }
            } else {
                messageHeaders.add(header);
            }
        }
        final HttpRequest httpRequest = new BasicHttpRequest(method, path);
        httpRequest.setVersion(HttpVersion.HTTP_2);
        httpRequest.setScheme(scheme);
        try {
            httpRequest.setAuthority(URIAuthority.create(authority));
        } catch (final URISyntaxException ex) {
            throw new ProtocolException(ex.getMessage(), ex);
        }
        httpRequest.setPath(path);
        for (int i = 0; i < messageHeaders.size(); i++) {
            httpRequest.addHeader(messageHeaders.get(i));
        }
        return httpRequest;
    }

    @Override
    public List<Header> convert(final HttpRequest message) throws HttpException {
        final boolean optionMethod = Method.CONNECT.name().equalsIgnoreCase(message.getMethod());
        final List<Header> headers = new ArrayList<>();
        headers.add(new BasicHeader(H2PseudoRequestHeaders.METHOD, message.getMethod(), false));
        if (optionMethod) {
            headers.add(new BasicHeader(H2PseudoRequestHeaders.AUTHORITY, message.getAuthority(), false));
        }  else {
            headers.add(new BasicHeader(H2PseudoRequestHeaders.SCHEME, message.getScheme(), false));
            if (message.getAuthority() != null) {
                headers.add(new BasicHeader(H2PseudoRequestHeaders.AUTHORITY, message.getAuthority(), false));
            }
            headers.add(new BasicHeader(H2PseudoRequestHeaders.PATH, message.getPath(), false));
        }

        for (final Iterator<Header> it = message.headerIterator(); it.hasNext(); ) {
            final Header header = it.next();
            final String name = header.getName();
            final String value = header.getValue();
            headers.add(new BasicHeader(name, value));
        }

        return headers;
    }

}
