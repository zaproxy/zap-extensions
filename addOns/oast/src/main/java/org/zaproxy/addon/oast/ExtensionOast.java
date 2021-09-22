/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2021 The ZAP Development Team
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
package org.zaproxy.addon.oast;

import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.db.DatabaseException;
import org.parosproxy.paros.extension.ExtensionAdaptor;
import org.parosproxy.paros.extension.ExtensionHook;
import org.parosproxy.paros.extension.SessionChangedListener;
import org.parosproxy.paros.model.HistoryReference;
import org.parosproxy.paros.model.Session;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.zaproxy.addon.oast.services.boast.BoastOptionsPanelTab;
import org.zaproxy.addon.oast.services.boast.BoastService;
import org.zaproxy.addon.oast.services.callback.CallbackOptionsPanelTab;
import org.zaproxy.addon.oast.services.callback.CallbackService;
import org.zaproxy.addon.oast.services.interactsh.InteractshOptionsPanelTab;
import org.zaproxy.addon.oast.services.interactsh.InteractshService;
import org.zaproxy.addon.oast.ui.OastOptionsPanel;
import org.zaproxy.addon.oast.ui.OastPanel;
import org.zaproxy.zap.extension.help.ExtensionHelp;
import org.zaproxy.zap.utils.ThreadUtils;

public class ExtensionOast extends ExtensionAdaptor {

    private static final String NAME = ExtensionOast.class.getSimpleName();
    private static final Logger LOGGER = LogManager.getLogger(ExtensionOast.class);
    static final int HISTORY_TYPE_OAST = 22; // Equal to HistoryReference.TYPE_OAST

    private final Map<String, OastService> services = new HashMap<>();
    private OastOptionsPanel oastOptionsPanel;
    private OastPanel oastPanel;
    private BoastService boastService;
    private CallbackService callbackService;
    private InteractshService interactshService;

    public ExtensionOast() {
        super(NAME);
    }

    @Override
    public void init() {
        boastService = new BoastService();
        callbackService = new CallbackService();
        interactshService = new InteractshService();
    }

    @Override
    public void hook(ExtensionHook extensionHook) {
        super.hook(extensionHook);

        registerOastService(boastService);
        registerOastService(callbackService);
        registerOastService(interactshService);

        extensionHook.addApiImplementor(new OastApi());
        extensionHook.addSessionListener(new OastSessionChangedListener());

        extensionHook.addOptionsParamSet(boastService.getParam());
        extensionHook.addOptionsParamSet(callbackService.getParam());
        extensionHook.addOptionsParamSet(interactshService.getParam());

        extensionHook.addOptionsChangedListener(boastService);
        extensionHook.addOptionsChangedListener(callbackService);
        extensionHook.addOptionsChangedListener(interactshService);

        if (hasView()) {
            extensionHook.getHookView().addOptionPanel(getOastOptionsPanel());
            getOastOptionsPanel().addServicePanel(new BoastOptionsPanelTab(boastService));
            getOastOptionsPanel().addServicePanel(new CallbackOptionsPanelTab(callbackService));
            getOastOptionsPanel().addServicePanel(new InteractshOptionsPanelTab(interactshService));
            extensionHook.getHookView().addStatusPanel(getOastPanel());
            ExtensionHelp.enableHelpKey(getOastPanel(), "oast.tab");
        }
    }

    @Override
    public void optionsLoaded() {
        boastService.optionsLoaded();
        callbackService.optionsLoaded();
        interactshService.optionsLoaded();
    }

    @Override
    public void postInit() {
        boastService.startService();
        callbackService.startService();
        interactshService.startService();
    }

    public void deleteAllCallbacks() {
        try {
            ThreadUtils.invokeAndWaitHandled(() -> getOastPanel().clearOastRequests());
            this.getModel()
                    .getDb()
                    .getTableHistory()
                    .deleteHistoryType(
                            this.getModel().getSession().getSessionId(), HISTORY_TYPE_OAST);
        } catch (DatabaseException e) {
            LOGGER.error(e.getMessage(), e);
        }
    }

    private void registerOastService(OastService service) {
        if (service == null || service.getName().isEmpty()) {
            throw new IllegalArgumentException("Invalid Service Provided");
        }
        if (services.containsKey(service.getName())) {
            throw new IllegalArgumentException("Service Already Exists");
        }
        if (hasView()) {
            service.addOastRequestHandler(o -> getOastPanel().addOastRequest(o));
        }
        services.put(service.getName(), service);
    }

    private void unregisterOastService(OastService service) {
        services.remove(service.getName());
    }

    public Map<String, OastService> getOastServices() {
        return Collections.unmodifiableMap(services);
    }

    public BoastService getBoastService() {
        return boastService;
    }

    public CallbackService getCallbackService() {
        return callbackService;
    }

    public InteractshService getInteractshService() {
        return interactshService;
    }

    public void pollAllServices() {
        getOastServices().values().forEach(OastService::poll);
    }

    private OastOptionsPanel getOastOptionsPanel() {
        if (oastOptionsPanel == null) {
            oastOptionsPanel = new OastOptionsPanel();
        }
        return oastOptionsPanel;
    }

    public OastPanel getOastPanel() {
        if (oastPanel == null) {
            oastPanel = new OastPanel(this);
        }
        return oastPanel;
    }

    @Override
    public boolean supportsDb(String type) {
        return true;
    }

    @Override
    public boolean canUnload() {
        return true;
    }

    // TODO: Remove once targeting >= 2.11, refer to issue 6536.
    @Override
    public void unload() {
        stop();
    }

    @Override
    public void stop() {
        boastService.stopService();
        callbackService.stopService();
        interactshService.stopService();
        unregisterOastService(boastService);
        unregisterOastService(callbackService);
        unregisterOastService(interactshService);
    }

    private class OastSessionChangedListener implements SessionChangedListener {
        @Override
        public void sessionChanged(Session session) {
            ThreadUtils.invokeAndWaitHandled(
                    () -> {
                        getOastPanel().clearOastRequests();
                        addCallbacksFromDatabaseIntoCallbackPanel(session);
                    });
            getOastServices().values().forEach(OastService::sessionChanged);
            getOastServices().values().forEach(OastService::clearOastRequestHandlers);
            if (hasView()) {
                getOastServices()
                        .values()
                        .forEach(
                                s ->
                                        s.addOastRequestHandler(
                                                o -> getOastPanel().addOastRequest(o)));
            }
        }

        private void addCallbacksFromDatabaseIntoCallbackPanel(Session session) {
            if (session == null) {
                return;
            }

            try {
                List<Integer> historyIds =
                        getModel()
                                .getDb()
                                .getTableHistory()
                                .getHistoryIdsOfHistType(session.getSessionId(), HISTORY_TYPE_OAST);

                for (int historyId : historyIds) {
                    HistoryReference historyReference = new HistoryReference(historyId);
                    OastRequest request = OastRequest.create(historyReference);
                    getOastPanel().addOastRequest(request);
                }
            } catch (DatabaseException | HttpMalformedHeaderException e) {
                LOGGER.error(e.getMessage(), e);
            }
        }

        @Override
        public void sessionAboutToChange(Session session) {}

        @Override
        public void sessionScopeChanged(Session session) {}

        @Override
        public void sessionModeChanged(Control.Mode mode) {}
    }
}
