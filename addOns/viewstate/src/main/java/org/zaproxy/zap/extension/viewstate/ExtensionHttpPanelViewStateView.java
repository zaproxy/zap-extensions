/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2016 The ZAP Development Team
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
package org.zaproxy.zap.extension.viewstate;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import org.apache.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.extension.ExtensionAdaptor;
import org.parosproxy.paros.extension.ExtensionHook;
import org.zaproxy.zap.extension.brk.ExtensionBreak;
import org.zaproxy.zap.extension.httppanel.component.split.request.RequestSplitComponent;
import org.zaproxy.zap.extension.httppanel.component.split.response.ResponseSplitComponent;
import org.zaproxy.zap.extension.httppanel.view.HttpPanelView;
import org.zaproxy.zap.extension.httppanel.view.hex.ExtensionHttpPanelHexView;
import org.zaproxy.zap.view.HttpPanelManager;
import org.zaproxy.zap.view.HttpPanelManager.HttpPanelViewFactory;

public class ExtensionHttpPanelViewStateView extends ExtensionAdaptor {

    private static final List<Class<?>> EXTENSION_DEPENDENCIES;

    static {
        // Prepare a list of Extensions on which this extension depends
        List<Class<?>> dependencies = new ArrayList<>(1);
        dependencies.add(ExtensionBreak.class);
        dependencies.add(ExtensionHttpPanelHexView.class);
        EXTENSION_DEPENDENCIES = Collections.unmodifiableList(dependencies);
    }

    private static Logger logger = Logger.getLogger(ExtensionHttpPanelViewStateView.class);
    public static final String NAME = "ExtensionHttpPanelViewStateView";

    public ExtensionHttpPanelViewStateView() {
        super(NAME);
        initialize();
    }

    public ExtensionHttpPanelViewStateView(String name) {
        super(name);
        initialize();
    }

    private void initialize() {
        this.setOrder(25);
    }

    private void initViewFactories() {
        if (getView() != null) {
            HttpPanelManager.getInstance()
                    .addRequestViewFactory(
                            RequestSplitComponent.NAME, new RequestSplitBodyViewStateViewFactory());
            HttpPanelManager.getInstance()
                    .addResponseViewFactory(
                            ResponseSplitComponent.NAME,
                            new ResponseSplitBodyViewStateViewFactory());
        }
    }

    @Override
    public void hook(ExtensionHook extensionHook) {
        super.hook(extensionHook);
        initViewFactories();
    }

    @Override
    public boolean canUnload() {
        return true;
    }

    @Override
    public void unload() {
        if (getView() != null) {
            HttpPanelManager panelManager = HttpPanelManager.getInstance();
            panelManager.removeRequestViewFactory(
                    RequestSplitComponent.NAME, RequestSplitBodyViewStateViewFactory.NAME);
            panelManager.removeRequestViews(
                    RequestSplitComponent.NAME,
                    HttpPanelViewStateView.NAME,
                    RequestSplitComponent.ViewComponent.BODY);

            panelManager.removeResponseViewFactory(
                    ResponseSplitComponent.NAME, ResponseSplitBodyViewStateViewFactory.NAME);
            panelManager.removeResponseViews(
                    ResponseSplitComponent.NAME,
                    HttpPanelViewStateView.NAME,
                    ResponseSplitComponent.ViewComponent.BODY);
        }
    }

    private static class RequestSplitBodyViewStateViewFactory implements HttpPanelViewFactory {

        public static final String NAME = "RequestSplitBodyViewStateViewFactory";

        @Override
        public String getName() {
            return NAME;
        }

        @Override
        public HttpPanelView getNewView() {
            return new HttpPanelViewStateView(
                    new ViewStateModel(ViewStateModel.VS_ACTION_REQUEST, null), false);
        }

        @Override
        public Object getOptions() {
            return RequestSplitComponent.ViewComponent.BODY;
        }
    }

    private static class ResponseSplitBodyViewStateViewFactory implements HttpPanelViewFactory {

        public static final String NAME = "ResponseSplitBodyViewStateViewFactory";

        @Override
        public String getName() {
            return NAME;
        }

        @Override
        public HttpPanelView getNewView() {
            return new HttpPanelViewStateView(
                    new ViewStateModel(ViewStateModel.VS_ACTION_RESPONSE, null), false);
        }

        @Override
        public Object getOptions() {
            return ResponseSplitComponent.ViewComponent.BODY;
        }
    }

    @Override
    public String getDescription() {
        return Constant.messages.getString("viewstate.desc");
    }

    /** No database tables used, so all supported */
    @Override
    public boolean supportsDb(String type) {
        return true;
    }
}
