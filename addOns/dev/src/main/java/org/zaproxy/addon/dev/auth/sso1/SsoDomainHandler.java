/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2025 The ZAP Development Team
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
package org.zaproxy.addon.dev.auth.sso1;

import org.parosproxy.paros.core.proxy.ProxyListener;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpResponseHeader;

public class SsoDomainHandler implements ProxyListener {

    @Override
    public int getArrangeableListenerOrder() {
        // TODO Auto-generated method stub
        return 0;
    }

    @Override
    public boolean onHttpRequestSend(HttpMessage msg) {
        // TODO Auto-generated method stub
        System.out.println("SBSB proxy " + msg.getRequestHeader().getURI());
        msg.setResponseBody(
                "<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 3.2//EN\">\n"
                        + "<html><head></head><body><h1>WooHoo</h1>\n"
                        + "It worked SSO1 test\n"
                        + "</body></html>");
        try {
            msg.setResponseHeader(
                    new HttpResponseHeader(
                            "HTTP/1.1 200 OK\r\n" + "Content-Type: text/html; charset=UTF-8"));
        } catch (HttpMalformedHeaderException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        msg.getResponseHeader().setContentLength(msg.getResponseBody().length());
        return true;
    }

    @Override
    public boolean onHttpResponseReceive(HttpMessage msg) {
        // TODO Auto-generated method stub
        return true;
    }
}
