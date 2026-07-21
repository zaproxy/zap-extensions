/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2026 The ZAP Development Team
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
package org.zaproxy.addon.network.internal.server.http.handlers;

import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.function.Supplier;
import java.util.regex.Pattern;
import java.util.stream.Stream;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpSender;
import org.parosproxy.paros.network.HttpStatusCode;
import org.zaproxy.addon.network.server.HttpMessageHandler;
import org.zaproxy.addon.network.server.HttpMessageHandlerContext;

/**
 * A {@link HttpMessageHandler} that handles browser-initiated requests (e.g. update checks,
 * telemetry) according to the configured {@link Action}.
 */
public class BrowserRequestHandler extends HttpSenderHandler {

    /** The action to take for browser-initiated requests (e.g. update checks, telemetry). */
    public enum Action {

        /** Browser-initiated requests are blocked with a 403 Forbidden response. */
        BLOCK,

        /** Browser-initiated requests are sent silently without notification. */
        HIDE,

        /** No action, browser-initiated requests are processed as any other request. */
        NONE,
        ;

        @Override
        public String toString() {
            return Constant.messages.getString(
                    "network.ui.options.localservers.browserrequestaction."
                            + name().toLowerCase(Locale.ROOT));
        }
    }

    private static final List<Pattern> URL_PATTERNS =
            Stream.of(
                            // Chrome
                            "^\\Qhttp://clients2.google.com/time/1/current\\E",
                            "^\\Qhttps://accounts.google.com/ListAccounts?gpsia\\E",
                            "^\\Qhttps://android.clients.google.com/c2dm/register3\\E",
                            "^\\Qhttps://android.clients.google.com/checkin\\E",
                            "^\\Qhttps://optimizationguide-pa.googleapis.com/\\E",
                            "^\\Qhttps://www.google.com/async/folae\\E",
                            "^\\Qhttps://www.googleapis.com/chromewebstore/\\E",

                            // Edge
                            "^\\Qhttp://edge.microsoft.com/\\E",
                            "^\\Qhttp://msedge.\\E[a-z]\\Q.tlu.dl.delivery.mp.microsoft.com/\\E",
                            "^\\Qhttps://data-edge.smartscreen.microsoft.com/\\E",
                            "^\\Qhttps://edge.microsoft.com/\\E",
                            "^\\Qhttps://functional.events.data.microsoft.com/\\E",
                            "^\\Qhttps://msedgedriver.microsoft.com/\\E",
                            "^\\Qhttps://nav-edge.smartscreen.microsoft.com/api/browser/\\E",
                            "^\\Qhttps://self.events.data.microsoft.com/\\E",
                            "^\\Qhttps://telem-edge.smartscreen.microsoft.com/api/browser/\\E",
                            "^\\Qhttps://www.bing.com/api/shopping/v1/user/shoppingsettings\\E",
                            "^\\Qhttps://www.bing.com/bloomfilterfiles/ExpandedDomainsFilterGlobal.json\\E",

                            // Firefox
                            "^\\Qhttp://detectportal.firefox.com/\\E",
                            "^\\Qhttps://archive.mozilla.org/\\E",
                            "^\\Qhttps://content-signature-2.cdn.mozilla.net\\E",
                            "^\\Qhttps://firefox-settings-attachments.cdn.mozilla.net/\\E",
                            "^\\Qhttps://firefox.settings.services.mozilla.com/\\E",
                            "^\\Qhttps://incoming.telemetry.mozilla.org/\\E",
                            "^\\Qhttps://merino.services.mozilla.com/api\\E",
                            "^\\Qhttps://mozilla-ohttp.fastly-edge.com/\\E",
                            "^\\Qhttps://www.google.com/complete/search\\E",

                            // Selenium (happen while using browsers)
                            "^\\Qhttps://googlechromelabs.github.io/chrome-for-testing/known-good-versions-with-downloads.json\\E",
                            "^\\Qhttps://plausible.io/api/event\\E",
                            "^\\Qhttps://raw.githubusercontent.com/SeleniumHQ/selenium/trunk/common/geckodriver/geckodriver-support.json\\E")
                    .map(Pattern::compile)
                    .toList();

    private final Supplier<Action> actionSupplier;

    /**
     * Constructs a {@code BrowserRequestHandler}.
     *
     * @param actionSupplier supplier of the current browser request action.
     * @param httpSender the HTTP sender used to forward requests silently.
     * @throws NullPointerException if any argument is {@code null}.
     */
    public BrowserRequestHandler(Supplier<Action> actionSupplier, HttpSender httpSender) {
        super(httpSender);
        this.actionSupplier = Objects.requireNonNull(actionSupplier);
    }

    @Override
    public void handleMessage(HttpMessageHandlerContext ctx, HttpMessage msg) {
        if (!ctx.isFromClient()) {
            return;
        }

        Action action = actionSupplier.get();
        if (action == Action.NONE) {
            return;
        }

        String uri = msg.getRequestHeader().getURI().toString();
        boolean matches = URL_PATTERNS.stream().anyMatch(p -> p.matcher(uri).find());
        if (!matches) {
            return;
        }

        ctx.overridden();

        if (action == Action.BLOCK) {
            setErrorResponse(msg, HttpStatusCode.FORBIDDEN, "Forbidden", "Forbidden");
            return;
        }

        send(ctx, msg, true);
    }
}
