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

import static java.util.Collections.synchronizedMap;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.apache.commons.collections.map.AbstractReferenceMap;
import org.apache.commons.collections.map.ReferenceMap;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.db.DatabaseException;
import org.parosproxy.paros.extension.Extension;
import org.parosproxy.paros.extension.ExtensionAdaptor;
import org.parosproxy.paros.extension.ExtensionHook;
import org.parosproxy.paros.extension.SessionChangedListener;
import org.parosproxy.paros.model.HistoryReference;
import org.parosproxy.paros.model.OptionsParam;
import org.parosproxy.paros.model.Session;
import org.parosproxy.paros.network.HttpMalformedHeaderException;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.network.ExtensionNetwork;
import org.zaproxy.addon.oast.services.boast.BoastOptionsPanelTab;
import org.zaproxy.addon.oast.services.boast.BoastService;
import org.zaproxy.addon.oast.services.callback.CallbackOptionsPanelTab;
import org.zaproxy.addon.oast.services.callback.CallbackService;
import org.zaproxy.addon.oast.services.interactsh.InteractshOptionsPanelTab;
import org.zaproxy.addon.oast.services.interactsh.InteractshService;
import org.zaproxy.addon.oast.ui.GeneralOastOptionsPanelTab;
import org.zaproxy.addon.oast.ui.OastOptionsPanel;
import org.zaproxy.addon.oast.ui.OastPanel;
import org.zaproxy.zap.extension.alert.ExtensionAlert;
import org.zaproxy.zap.extension.help.ExtensionHelp;
import org.zaproxy.zap.utils.ThreadUtils;

public class ExtensionOast extends ExtensionAdaptor {

    // TODO: Remove on next ZAP release
    public static final int HTTP_SENDER_OAST_INITIATOR = 16;

    public static final String OAST_ALERT_TAG_KEY = "OUT_OF_BAND";
    public static final String OAST_ALERT_TAG_VALUE =
            "https://www.zaproxy.org/docs/desktop/addons/oast-support/";

    private static final String NAME = ExtensionOast.class.getSimpleName();
    private static final Logger LOGGER = LogManager.getLogger(ExtensionOast.class);

    private static final List<Class<? extends Extension>> DEPENDENCIES =
            Collections.unmodifiableList(Arrays.asList(ExtensionNetwork.class));

    private final Map<String, OastService> services = new HashMap<>();

    @SuppressWarnings("unchecked")
    private final Map<String, Alert> alertCache =
            synchronizedMap(new ReferenceMap(AbstractReferenceMap.HARD, AbstractReferenceMap.SOFT));

    private OastOptionsPanel oastOptionsPanel;
    private OastPanel oastPanel;
    private OastParam oastParam;
    private BoastService boastService;
    private CallbackService callbackService;
    private InteractshService interactshService;

    public ExtensionOast() {
        super(NAME);
    }

    @Override
    public List<Class<? extends Extension>> getDependencies() {
        return DEPENDENCIES;
    }

    @Override
    public void init() {
        boastService = new BoastService();
        callbackService =
                new CallbackService(
                        OastRequest::create,
                        Control.getSingleton()
                                .getExtensionLoader()
                                .getExtension(ExtensionNetwork.class));
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

        oastParam = new OastParam();
        extensionHook.addOptionsParamSet(oastParam);
        extensionHook.addOptionsParamSet(boastService.getParam());
        extensionHook.addOptionsParamSet(callbackService.getParam());
        extensionHook.addOptionsParamSet(interactshService.getParam());

        extensionHook.addOptionsChangedListener(this::optionsChanged);
        extensionHook.addOptionsChangedListener(boastService);
        extensionHook.addOptionsChangedListener(callbackService);
        extensionHook.addOptionsChangedListener(interactshService);

        if (hasView()) {
            extensionHook.getHookView().addOptionPanel(getOastOptionsPanel());
            getOastOptionsPanel().addServicePanel(new GeneralOastOptionsPanelTab());
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

    private void optionsChanged(OptionsParam optionsParam) {
        getOastServices().values().forEach(OastService::fireOastStateChanged);
    }

    public void deleteAllCallbacks() {
        try {
            if (hasView()) {
                ThreadUtils.invokeAndWaitHandled(() -> getOastPanel().clearOastRequests());
            }
            this.getModel()
                    .getDb()
                    .getTableHistory()
                    .deleteHistoryType(
                            this.getModel().getSession().getSessionId(),
                            HistoryReference.TYPE_OAST);
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
        service.addOastRequestHandler(this::activeScanAlertOastRequestHandler);
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

    /**
     * @return the selected external OAST service (i.e. excluding Callbacks) for usage in active
     *     scan rules, or {@code null} if no service is selected.
     */
    public OastService getActiveScanOastService() {
        if (OastParam.NO_ACTIVE_SCAN_SERVICE_SELECTED_OPTION.equals(
                oastParam.getActiveScanServiceName())) {
            return null;
        }
        return getOastServices().get(oastParam.getActiveScanServiceName());
    }

    public String registerAlertAndGetPayloadForCallbackService(Alert alert, String handler) {
        String payload = callbackService.getNewPayload(handler);
        alertCache.put(payload, alert);
        return payload;
    }

    public String registerAlertAndGetPayload(Alert alert) throws Exception {
        if (getActiveScanOastService() != null) {
            String payload = getActiveScanOastService().getNewPayload();
            alertCache.put(payload, alert);
            return payload;
        }
        return null;
    }

    @SuppressWarnings("unchecked")
    private void activeScanAlertOastRequestHandler(OastRequest request) {
        try {
            HttpMessage oastReceivedMsg = request.getHistoryReference().getHttpMessage();
            String uri = oastReceivedMsg.getRequestHeader().getURI().toString();
            Alert alert;
            synchronized (alertCache) {
                alert =
                        alertCache.entrySet().stream()
                                .filter(it -> uri.contains(it.getKey()))
                                .findAny()
                                .map(it -> it.getValue())
                                .orElse(null);
            }
            if (alert == null) {
                LOGGER.warn(
                        "Soft reference to alert object for interaction at {} expired. Not raising alert.",
                        uri);
                return;
            }

            alert.setOtherInfo(
                    alert.getOtherInfo()
                            + '\n'
                            + Constant.messages.getString("oast.alert.otherinfo.request")
                            + '\n'
                            + oastReceivedMsg.getRequestHeader()
                            + oastReceivedMsg.getRequestBody()
                            + '\n'
                            + Constant.messages.getString("oast.alert.otherinfo.response")
                            + '\n'
                            + oastReceivedMsg.getResponseHeader()
                            + oastReceivedMsg.getResponseBody()
                            + "\n--------------------------------");
            if (alert.getAlertId() == -1) {
                Map<String, String> alertTags = new HashMap<>(alert.getTags());
                alertTags.putIfAbsent(OAST_ALERT_TAG_KEY, OAST_ALERT_TAG_VALUE);
                alert.setTags(alertTags);
                alert.setEvidence(oastReceivedMsg.getRequestHeader().getPrimeHeader());
                Control.getSingleton()
                        .getExtensionLoader()
                        .getExtension(ExtensionAlert.class)
                        .alertFound(alert, null);
            } else {
                Control.getSingleton()
                        .getExtensionLoader()
                        .getExtension(ExtensionAlert.class)
                        .updateAlert(alert);
            }
        } catch (Exception e) {
            LOGGER.error("Could not handle OAST request.", e);
        }
    }

    @Override
    public boolean supportsDb(String type) {
        return true;
    }

    @Override
    public boolean canUnload() {
        return true;
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

    @Override
    public String getUIName() {
        return Constant.messages.getString("oast.ext.name");
    }

    @Override
    public String getDescription() {
        return Constant.messages.getString("oast.ext.description");
    }

    private class OastSessionChangedListener implements SessionChangedListener {
        @Override
        public void sessionChanged(Session session) {
            if (session != null && hasView()) {
                ThreadUtils.invokeAndWaitHandled(
                        () -> {
                            getOastPanel().clearOastRequests();
                            addCallbacksFromDatabaseIntoCallbackPanel(session);
                        });
            }
            getOastServices().values().forEach(OastService::sessionChanged);
            getOastServices().values().forEach(OastService::clearOastRequestHandlers);
            alertCache.clear();
            for (OastService s : getOastServices().values()) {
                if (hasView()) {
                    s.addOastRequestHandler(o -> getOastPanel().addOastRequest(o));
                }
                s.addOastRequestHandler(ExtensionOast.this::activeScanAlertOastRequestHandler);
            }
        }

        private void addCallbacksFromDatabaseIntoCallbackPanel(Session session) {
            try {
                List<Integer> historyIds =
                        getModel()
                                .getDb()
                                .getTableHistory()
                                .getHistoryIdsOfHistType(
                                        session.getSessionId(), HistoryReference.TYPE_OAST);

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
