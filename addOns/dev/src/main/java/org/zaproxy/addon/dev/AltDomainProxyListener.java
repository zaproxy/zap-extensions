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
package org.zaproxy.addon.dev;

import java.util.HashMap;
import java.util.Map;
import org.apache.commons.httpclient.URIException;
import org.parosproxy.paros.core.proxy.ProxyListener;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.model.SessionStructure;

public class AltDomainProxyListener implements ProxyListener {

    private Map<String, ProxyListener> domainMap = new HashMap<>();

    @Override
    public int getArrangeableListenerOrder() {
        return 0;
    }

    public void addDomainListener(String domain, ProxyListener listener) {
        System.out.println("SBSB register domain " + domain);
        this.domainMap.put(domain, listener);
    }

    @Override
    public boolean onHttpRequestSend(HttpMessage msg) {
        try {
            String host = SessionStructure.getHostName(msg);
            System.out.println("SBSB proxy host " + host + " : " + msg.getRequestHeader().getURI());
            ProxyListener proxy = domainMap.get(host);
            if (proxy != null) {
                System.out.println("SBSB passing to handler for " + host);
                return proxy.onHttpRequestSend(msg);
            }
        } catch (URIException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        /*

        System.out.println("SBSB proxy " + msg.getRequestHeader().getURI());
        if ("https://sso.zap/".equals(msg.getRequestHeader().getURI().toString())
                || "http://sso.zap/".equals(msg.getRequestHeader().getURI().toString())) {
            msg.setResponseBody(
                    "<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 3.2//EN\">\n"
                            + "<html><head></head><body><h1>WooHoo</h1>\n"
                            + "It worked :grin:'\n"
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
            // return true;
             *
        }
             */
        return true;
    }

    @Override
    public boolean onHttpResponseReceive(HttpMessage msg) {
        try {
            String host = SessionStructure.getHostName(msg);
            ProxyListener proxy = domainMap.get(host);
            if (proxy != null) {
                return proxy.onHttpResponseReceive(msg);
            }
        } catch (URIException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        return true;
    }
}
