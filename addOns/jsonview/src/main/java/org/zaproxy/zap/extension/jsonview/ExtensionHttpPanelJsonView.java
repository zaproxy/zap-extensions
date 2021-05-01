/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2018 The ZAP Development Team
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
package org.zaproxy.zap.extension.jsonview;

import java.util.Locale;
import org.parosproxy.paros.extension.ExtensionAdaptor;
import org.parosproxy.paros.extension.ExtensionHook;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.httppanel.Message;
import org.zaproxy.zap.extension.httppanel.component.split.request.RequestSplitComponent;
import org.zaproxy.zap.extension.httppanel.component.split.response.ResponseSplitComponent;
import org.zaproxy.zap.extension.httppanel.view.HttpPanelDefaultViewSelector;
import org.zaproxy.zap.extension.httppanel.view.HttpPanelView;
import org.zaproxy.zap.extension.httppanel.view.impl.models.http.request.RequestBodyStringHttpPanelViewModel;
import org.zaproxy.zap.extension.httppanel.view.impl.models.http.response.ResponseBodyStringHttpPanelViewModel;
import org.zaproxy.zap.view.HttpPanelManager;
import org.zaproxy.zap.view.HttpPanelManager.HttpPanelDefaultViewSelectorFactory;
import org.zaproxy.zap.view.HttpPanelManager.HttpPanelViewFactory;

public class ExtensionHttpPanelJsonView extends ExtensionAdaptor {

    public static final String NAME = "ExtensionHttpPanelJsonView";

    public ExtensionHttpPanelJsonView() {
        super(NAME);
    }

    @Override
    public void hook(ExtensionHook extensionHook) {
        super.hook(extensionHook);

        if (getView() != null) {
            HttpPanelManager panelManager = HttpPanelManager.getInstance();
            // add the view factories for http requests and responses
            panelManager.addRequestViewFactory(
                    RequestSplitComponent.NAME, new RequestJsonViewFactory());
            panelManager.addResponseViewFactory(
                    ResponseSplitComponent.NAME, new ResponseJsonViewFactory());
            // add default view selectors
            panelManager.addRequestDefaultViewSelectorFactory(
                    RequestSplitComponent.NAME,
                    new JsonDefaultViewSelectorFactory(
                            RequestSplitComponent.NAME, RequestSplitComponent.ViewComponent.BODY));
            panelManager.addResponseDefaultViewSelectorFactory(
                    ResponseSplitComponent.NAME,
                    new JsonDefaultViewSelectorFactory(
                            ResponseSplitComponent.NAME,
                            ResponseSplitComponent.ViewComponent.BODY));
        }
    }

    @Override
    public boolean canUnload() {
        return true;
    }

    @Override
    public void unload() {
        if (getView() != null) {
            HttpPanelManager panelManager = HttpPanelManager.getInstance();
            // remove views and their factories
            panelManager.removeRequestViewFactory(
                    RequestSplitComponent.NAME, RequestJsonViewFactory.NAME);
            panelManager.removeRequestViews(
                    RequestSplitComponent.NAME,
                    HttpPanelJsonView.NAME,
                    RequestSplitComponent.ViewComponent.BODY);
            panelManager.removeResponseViewFactory(
                    ResponseSplitComponent.NAME, ResponseJsonViewFactory.NAME);
            panelManager.removeResponseViews(
                    ResponseSplitComponent.NAME,
                    HttpPanelJsonView.NAME,
                    ResponseSplitComponent.ViewComponent.BODY);
            // remove default view selectors and their factories
            panelManager.removeRequestDefaultViewSelectorFactory(
                    RequestSplitComponent.NAME, JsonDefaultViewSelectorFactory.NAME);
            panelManager.removeRequestDefaultViewSelectors(
                    RequestSplitComponent.NAME,
                    JsonDefaultViewSelector.NAME,
                    RequestSplitComponent.ViewComponent.BODY);
            panelManager.removeResponseDefaultViewSelectorFactory(
                    ResponseSplitComponent.NAME, JsonDefaultViewSelectorFactory.NAME);
            panelManager.removeResponseDefaultViewSelectors(
                    ResponseSplitComponent.NAME,
                    JsonDefaultViewSelector.NAME,
                    ResponseSplitComponent.ViewComponent.BODY);
        }
        super.unload();
    }

    private static final class RequestJsonViewFactory implements HttpPanelViewFactory {
        public static final String NAME = "RequestJsonViewFactory";

        @Override
        public String getName() {
            return NAME;
        }

        @Override
        public HttpPanelView getNewView() {
            return new HttpPanelJsonView(new RequestBodyStringHttpPanelViewModel());
        }

        @Override
        public Object getOptions() {
            return RequestSplitComponent.ViewComponent.BODY;
        }
    }

    private static final class ResponseJsonViewFactory implements HttpPanelViewFactory {
        public static final String NAME = "ResponseJsonViewFactory";

        @Override
        public String getName() {
            return NAME;
        }

        @Override
        public HttpPanelView getNewView() {
            return new HttpPanelJsonView(new ResponseBodyStringHttpPanelViewModel());
        }

        @Override
        public Object getOptions() {
            return ResponseSplitComponent.ViewComponent.BODY;
        }
    }

    private static final class JsonDefaultViewSelector implements HttpPanelDefaultViewSelector {
        private static final String NAME = "JsonDefaultViewSelector";
        private Object options;

        JsonDefaultViewSelector(Object options) {
            this.options = options;
        }

        @Override
        public String getName() {
            return NAME;
        }

        @Override
        public boolean matchToDefaultView(Message message) {
            if (message == null) {
                // called with null when deleting the view, ie. when changing from split to combined
                // view
                return false;
            }
            if (message instanceof HttpMessage) {
                HttpMessage httpMessage = (HttpMessage) message;
                HttpHeader header;
                if (this.options == RequestSplitComponent.NAME) {
                    header = httpMessage.getRequestHeader();
                } else if (this.options == ResponseSplitComponent.NAME) {
                    header = httpMessage.getResponseHeader();
                } else {
                    return false;
                }
                String contentType = header.getHeader(HttpHeader.CONTENT_TYPE);
                if (contentType == null) {
                    return false;
                }
                if (contentType.toLowerCase(Locale.ROOT).contains("application/json")) {
                    return true;
                }
            }
            return false;
        }

        @Override
        public String getViewName() {
            return HttpPanelJsonView.NAME;
        }

        @Override
        public int getOrder() {
            return 0;
        }
    }

    private static final class JsonDefaultViewSelectorFactory
            implements HttpPanelDefaultViewSelectorFactory {
        public static final String NAME = "JsonDefaultViewSelector";
        private Object selectorOptions;
        private Object factoryOptions;

        JsonDefaultViewSelectorFactory(Object selectorOptions, Object factoryOptions) {
            this.factoryOptions = factoryOptions;
            this.selectorOptions = selectorOptions;
        }

        @Override
        public String getName() {
            return NAME;
        }

        @Override
        public HttpPanelDefaultViewSelector getNewDefaultViewSelector() {
            return new JsonDefaultViewSelector(this.selectorOptions);
        }

        @Override
        public Object getOptions() {
            return this.factoryOptions;
        }
    }
}
