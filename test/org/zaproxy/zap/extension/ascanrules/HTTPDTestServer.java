/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2016 The ZAP development team
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
package org.zaproxy.zap.extension.ascanrules;

import java.util.ArrayList;
import java.util.List;

import fi.iki.elonen.NanoHTTPD;

public class HTTPDTestServer extends NanoHTTPD {
    
    private List<NanoServerHandler> handlers = 
            new ArrayList<NanoServerHandler>();

    public HTTPDTestServer(int port) {
        super(port);
    }
    @Override
    public Response serve(IHTTPSession session) {
        String uri = session.getUri();
        for (NanoServerHandler handler : handlers) {
            if (uri.startsWith("/" + handler.getName() + "/")) {
                return handler.serve(session);
            }
        }
        return null;
    }

    public void addHandler (NanoServerHandler handler) {
        this.handlers.add(handler);
    }

    public void removeHandler (NanoServerHandler handler) {
        this.handlers.remove(handler);
    }

}
