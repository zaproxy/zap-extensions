/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2020 The ZAP Development Team
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
package org.zaproxy.zap.extension.frontendscanner;

import java.util.List;
import net.htmlparser.jericho.Element;
import net.htmlparser.jericho.OutputDocument;
import net.htmlparser.jericho.Source;
import org.apache.log4j.Logger;
import org.parosproxy.paros.core.proxy.ProxyListener;
import org.parosproxy.paros.extension.history.ProxyListenerLog;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.api.API;

/** The {@link ProxyListener} the {@link ExtensionFrontEndScanner} relies on. */
public class FrontEndScannerProxyListener implements ProxyListener {
    private static final Logger LOGGER = Logger.getLogger(FrontEndScannerProxyListener.class);

    private final FrontEndScannerAPI api;
    private final FrontEndScannerOptions options;

    private static final String[] CSP_HEADERS = {
        "Content-Security-Policy", "X-Content-Security-Policy", "X-WebKit-CSP"
    };

    public FrontEndScannerProxyListener(FrontEndScannerAPI api, FrontEndScannerOptions options) {
        this.api = api;
        this.options = options;
    }

    @Override
    public boolean onHttpRequestSend(HttpMessage msg) {
        return true;
    }

    @Override
    public boolean onHttpResponseReceive(HttpMessage msg) {
        if (options.isEnabled() && msg.getResponseHeader().isHtml()) {
            try {
                String html = msg.getResponseBody().toString();

                if (msg.getHistoryRef() != null) {
                    String host = msg.getRequestHeader().getHeader("host");
                    String frontEndApiUrl =
                            API.getInstance().getCallBackUrl(this.api, "https://" + host);

                    int historyReferenceId = msg.getHistoryRef().getHistoryId();
                    String scriptToInject = getScriptToInject(frontEndApiUrl, historyReferenceId);

                    OutputDocument newResponseBody = makeNewDocument(html, scriptToInject);

                    msg.getResponseBody().setBody(newResponseBody.toString());
                    int newLength = msg.getResponseBody().length();
                    msg.getResponseHeader().setContentLength(newLength);

                    for (String header : CSP_HEADERS) {
                        msg.getResponseHeader().setHeader(header, null);
                    }
                } else {
                    LOGGER.debug("No historyRef found in the HttpMessage.");
                }
            } catch (Exception e) {
                LOGGER.error(e.getMessage(), e);
            }
        }
        return true;
    }

    private static OutputDocument makeNewDocument(String originalHtml, String scriptToInject) {
        Source document = new Source(originalHtml);

        List<Element> heads = document.getAllElements("head");
        Element head = heads.isEmpty() ? null : heads.get(0);
        List<Element> htmls = document.getAllElements("html");
        Element html = htmls.isEmpty() ? null : htmls.get(0);

        int insertPosition = getInsertPosition(head, html);

        StringBuilder contentToInjectBuilder = new StringBuilder(scriptToInject);

        if (head == null) {
            contentToInjectBuilder.insert(0, "<head>");
            contentToInjectBuilder.append("</head>");
        }

        OutputDocument newHtml = new OutputDocument(document);
        newHtml.insert(insertPosition, contentToInjectBuilder.toString());

        return newHtml;
    }

    private static int getInsertPosition(Element head, Element html) {
        // The payload needs to be inserted in front of as many elements as possible;
        // But still after the `<meta>` tag (if there is any).
        if (head == null) {
            return (html == null) ? 0 : html.getStartTag().getEnd();
        }

        List<Element> headChildren = head.getChildElements();
        int numberOfChildren = headChildren.size();

        if (numberOfChildren == 0) {
            return head.getStartTag().getEnd();
        }

        List<Element> metaElements = head.getAllElements("meta");
        int numberOfMetaTags = metaElements.size();

        if (numberOfMetaTags == 0) {
            return head.getChildElements().get(0).getBegin();
        } else {
            return metaElements.get(numberOfMetaTags - 1).getEnd();
        }
    }

    private static String getScriptToInject(String frontEndApiUrl, int historyReferenceId) {
        StringBuilder scriptToInjectBuilder =
                new StringBuilder(200)
                        .append("<script src='")
                        .append(frontEndApiUrl)
                        .append("?action=getFile")
                        .append("&filename=front-end-scanner.js")
                        .append("&historyReferenceId=")
                        .append(historyReferenceId)
                        .append("'></script>");

        return scriptToInjectBuilder.toString();
    }

    @Override
    public int getArrangeableListenerOrder() {
        // Need to run after the HistoryReference has been saved to the database
        return ProxyListenerLog.PROXY_LISTENER_ORDER + 42;
    }
}
