/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2017 The ZAP development team
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.zaproxy.zap.extension.openapi;

import java.io.IOException;

import org.apache.commons.io.IOUtils;
import org.parosproxy.paros.network.HttpHeader;

import fi.iki.elonen.NanoHTTPD.IHTTPSession;
import fi.iki.elonen.NanoHTTPD.Response;

public abstract class NanoServerHandler {

    private String name;
    
    public NanoServerHandler (String name) {
        this.name = name;
    }
    
    public String getName() {
        return name;
    }
    
    abstract Response serve(IHTTPSession session);

    /**
     * Consumes the request body.
     *
     * @param session the session that has the request
     */
    protected void consumeBody(IHTTPSession session) {
        try {
            session.getInputStream().skip(getBodySize(session));
        } catch (IOException e) {
            System.err.println("Failed to consume body:");
            e.printStackTrace();
        }
    }

    /**
     * Gets the size of the request body.
     *
     * @param session the session that has the request
     * @return the size of the body
     */
    protected int getBodySize(IHTTPSession session) {
        String contentLengthHeader = session.getHeaders().get(HttpHeader.CONTENT_LENGTH.toLowerCase());
        if (contentLengthHeader == null) {
            return 0;
        }

        int contentLength = 0;
        try {
            contentLength = Integer.parseInt(contentLengthHeader);
        } catch (NumberFormatException e) {
            System.err.println("Failed to parse " + HttpHeader.CONTENT_LENGTH + " value: " + contentLengthHeader);
            e.printStackTrace();
            return 0;
        }

        if (contentLength <= 0) {
            return 0;
        }
        return contentLength;
    }

    /**
     * Gets the request body.
     *
     * @param session the session that has the request
     * @return the body
     */
    public String getBody(IHTTPSession session) {
        int contentLength = getBodySize(session);
        if (contentLength == 0) {
            return "";
        }

        byte[] bytes = new byte[contentLength];
        try {
            IOUtils.readFully(session.getInputStream(), bytes);
        } catch (IOException e) {
            System.err.println("Failed to read the body:");
            e.printStackTrace();
            return "";
        }
        return new String(bytes);
    }
}
