/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2024 The ZAP Development Team
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
package org.zaproxy.addon.grpc;

import org.parosproxy.paros.Constant;
import org.parosproxy.paros.extension.ExtensionAdaptor;
import org.parosproxy.paros.extension.ExtensionHook;
import org.zaproxy.addon.grpc.internal.HttpPanelGrpcView;
import org.zaproxy.zap.extension.httppanel.component.split.request.RequestSplitComponent;
import org.zaproxy.zap.extension.httppanel.component.split.response.ResponseSplitComponent;
import org.zaproxy.zap.extension.httppanel.view.HttpPanelView;
import org.zaproxy.zap.extension.httppanel.view.impl.models.http.request.RequestBodyByteHttpPanelViewModel;
import org.zaproxy.zap.extension.httppanel.view.impl.models.http.response.ResponseBodyByteHttpPanelViewModel;
import org.zaproxy.zap.view.HttpPanelManager;

public class ExtensionGrpc extends ExtensionAdaptor {

    public static final String NAME = "ExtensionGrpc";

    public ExtensionGrpc() {
        super(NAME);
    }

    @Override
    public void hook(ExtensionHook extensionHook) {
        super.hook(extensionHook);
        if (hasView()) {
            HttpPanelManager panelManager = HttpPanelManager.getInstance();
            panelManager.addRequestViewFactory(
                    RequestSplitComponent.NAME, new RequestGrpcViewFactory());
            panelManager.addResponseViewFactory(
                    ResponseSplitComponent.NAME, new ResponseGrpcViewFactory());
        }
    }

    @Override
    public boolean canUnload() {
        return true;
    }

    @Override
    public void unload() {
        if (hasView()) {
            HttpPanelManager panelManager = HttpPanelManager.getInstance();
            // remove views and their factories
            panelManager.removeRequestViewFactory(
                    RequestSplitComponent.NAME, RequestGrpcViewFactory.NAME);
            panelManager.removeRequestViews(
                    RequestSplitComponent.NAME,
                    HttpPanelGrpcView.NAME,
                    RequestSplitComponent.ViewComponent.BODY);
            panelManager.removeResponseViewFactory(
                    ResponseSplitComponent.NAME, ResponseGrpcViewFactory.NAME);
            panelManager.removeResponseViews(
                    ResponseSplitComponent.NAME,
                    HttpPanelGrpcView.NAME,
                    ResponseSplitComponent.ViewComponent.BODY);
        }
    }

    @Override
    public String getUIName() {
        return Constant.messages.getString("grpc.name");
    }

    @Override
    public String getDescription() {
        return Constant.messages.getString("grpc.desc");
    }

    private static final class ResponseGrpcViewFactory
            implements HttpPanelManager.HttpPanelViewFactory {
        public static final String NAME = "ResponseGrpcViewFactory";

        @Override
        public String getName() {
            return NAME;
        }

        @Override
        public HttpPanelView getNewView() {
            return new HttpPanelGrpcView(new ResponseBodyByteHttpPanelViewModel());
        }

        @Override
        public Object getOptions() {
            return ResponseSplitComponent.ViewComponent.BODY;
        }
    }

    private static final class RequestGrpcViewFactory
            implements HttpPanelManager.HttpPanelViewFactory {
        public static final String NAME = "RequestGrpcViewFactory";

        @Override
        public String getName() {
            return NAME;
        }

        @Override
        public HttpPanelView getNewView() {
            return new HttpPanelGrpcView(new RequestBodyByteHttpPanelViewModel());
        }

        @Override
        public Object getOptions() {
            return RequestSplitComponent.ViewComponent.BODY;
        }
    }
}
