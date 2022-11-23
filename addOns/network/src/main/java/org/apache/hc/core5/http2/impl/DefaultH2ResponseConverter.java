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

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

import org.apache.hc.core5.http.Header;
import org.apache.hc.core5.http.HttpException;
import org.apache.hc.core5.http.HttpResponse;
import org.apache.hc.core5.http.HttpVersion;
import org.apache.hc.core5.http.ProtocolException;
import org.apache.hc.core5.http.message.BasicHeader;
import org.apache.hc.core5.http.message.BasicHttpResponse;
import org.apache.hc.core5.http2.H2MessageConverter;
import org.apache.hc.core5.http2.H2PseudoResponseHeaders;

/**
 * HTTP/2 response converter, that does not validate the fields
 */
public class DefaultH2ResponseConverter implements H2MessageConverter<HttpResponse> {

    public final static DefaultH2ResponseConverter INSTANCE = new DefaultH2ResponseConverter();

    @Override
    public HttpResponse convert(final List<Header> headers) throws HttpException {
        String statusText = null;
        final List<Header> messageHeaders = new ArrayList<>();

        for (int i = 0; i < headers.size(); i++) {
            final Header header = headers.get(i);
            final String name = header.getName();
            final String value = header.getValue();

            if (name.startsWith(":")) {
                if (name.equals(H2PseudoResponseHeaders.STATUS) && statusText == null) {
                    statusText = value;
                }
            } else {
                messageHeaders.add(header);
            }

        }

        if (statusText == null) {
            throw new ProtocolException("Mandatory response header '%s' not found", H2PseudoResponseHeaders.STATUS);
        }
        final int statusCode;
        try {
            statusCode = Integer.parseInt(statusText);
        } catch (final NumberFormatException ex) {
            throw new ProtocolException("Invalid response status: " + statusText);
        }
        final HttpResponse response = new BasicHttpResponse(statusCode, null);
        response.setVersion(HttpVersion.HTTP_2);
        for (int i = 0; i < messageHeaders.size(); i++) {
            response.addHeader(messageHeaders.get(i));
        }
        return response;
    }

    @Override
    public List<Header> convert(final HttpResponse message) throws HttpException {
        final int code = message.getCode();
        if (code < 100 || code >= 600) {
            throw new ProtocolException("Response status %s is invalid", code);
        }
        final List<Header> headers = new ArrayList<>();
        headers.add(new BasicHeader(H2PseudoResponseHeaders.STATUS, Integer.toString(code), false));

        for (final Iterator<Header> it = message.headerIterator(); it.hasNext(); ) {
            final Header header = it.next();
            final String name = header.getName();
            final String value = header.getValue();
            headers.add(new BasicHeader(name, value));
        }
        return headers;
    }

}
