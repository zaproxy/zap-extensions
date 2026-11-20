/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2023 The ZAP Development Team
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
package org.zaproxy.addon.dev.auth.simpleJsonVerifyFails;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpRequestHeader;
import org.zaproxy.addon.dev.DevUtils;
import org.zaproxy.addon.dev.TestPage;
import org.zaproxy.addon.dev.TestProxyServer;
import org.zaproxy.addon.network.server.HttpMessageHandlerContext;

/** A page to set the number of verifications which succeed before they fail, or to reset it. */
public class SimpleJsonVerifyFailsConfigPage extends TestPage {

    private static final Logger LOGGER =
            LogManager.getLogger(SimpleJsonVerifyFailsConfigPage.class);

    public SimpleJsonVerifyFailsConfigPage(TestProxyServer server) {
        super(server, "config");
    }

    @Override
    public void handleMessage(HttpMessageHandlerContext ctx, HttpMessage msg) {
        if (HttpRequestHeader.POST.equals(msg.getRequestHeader().getMethod())) {
            if ("reset".equals(DevUtils.getFormParam(msg, "action"))) {
                getParent().setFailAfter(0);
            } else {
                try {
                    getParent()
                            .setFailAfter(
                                    Integer.parseInt(DevUtils.getFormParam(msg, "failAfter")));
                } catch (NumberFormatException e) {
                    // Invalid input - keep the current value.
                }
            }
        }

        String body =
                """
                <!DOCTYPE html>
                <html>
                <head><title>Verification Failure Config</title></head>
                <body>
                <h1>Verification Failure Config</h1>
                <p>Verifications succeed %d time(s) and then fail (0 = always fail).
                Verifications so far: %d.</p>
                <form method="POST">
                <input type="number" min="0" name="failAfter" value="%d">
                <button type="submit">Set</button>
                <button type="submit" name="action" value="reset">Reset (always fail)</button>
                </form>
                </body>
                </html>
                """
                        .formatted(
                                getParent().getFailAfter(),
                                getParent().getVerifications(),
                                getParent().getFailAfter());
        msg.setResponseBody(body);
        try {
            msg.setResponseHeader(
                    TestProxyServer.getDefaultResponseHeader(
                            TestProxyServer.CONTENT_TYPE_HTML_UTF8,
                            msg.getResponseBody().length()));
        } catch (HttpMalformedHeaderException e) {
            LOGGER.error(e.getMessage(), e);
        }
    }

    @Override
    public SimpleJsonVerifyFailsDir getParent() {
        return (SimpleJsonVerifyFailsDir) super.getParent();
    }
}
