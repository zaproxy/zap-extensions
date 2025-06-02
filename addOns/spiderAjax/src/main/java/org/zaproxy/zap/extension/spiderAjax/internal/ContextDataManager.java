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
package org.zaproxy.zap.extension.spiderAjax.internal;

import java.awt.BorderLayout;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.stream.Collectors;
import org.apache.commons.configuration.Configuration;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control.Mode;
import org.parosproxy.paros.extension.ExtensionHook;
import org.parosproxy.paros.extension.SessionChangedListener;
import org.parosproxy.paros.extension.ViewDelegate;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.model.Session;
import org.parosproxy.paros.model.Session.OnContextsChangedListener;
import org.zaproxy.zap.model.Context;
import org.zaproxy.zap.model.ContextDataFactory;
import org.zaproxy.zap.view.AbstractContextPropertiesPanel;
import org.zaproxy.zap.view.ContextPanelFactory;

/**
 * The manager of context data.
 *
 * <p>Manages data for each available context.
 */
public class ContextDataManager {

    private static final Logger LOGGER = LogManager.getLogger(ContextDataManager.class);

    private static final int TYPE_EXCLUDED_ELEMENTS = 700;

    private static final String DATA_FIELD_SEPARATOR = ";";

    private static final String CONFIG_BASE_KEY = Context.CONTEXT_CONFIG + ".ajaxSpider";
    private static final String CONFIG_EXCLUDED_ELEMENTS = CONFIG_BASE_KEY + ".excludedElements";
    private static final String CONFIG_EXCLUDED_ELEMENT =
            CONFIG_EXCLUDED_ELEMENTS + ".excludedElement";

    private final Model model;
    private final ViewDelegate view;
    private final Map<Integer, ContextData> entries;
    private final OnContextsChangedListener onContextsChangedListener;

    public ContextDataManager(Model model, ViewDelegate view, ExtensionHook extensionHook) {
        this.model = model;
        this.view = view;

        entries = new HashMap<>();

        extensionHook.addSessionListener(new SessionChangedListenerImpl());
        onContextsChangedListener = new OnContextsChangedListenerImpl();
        Model.getSingleton().getSession().addOnContextsChangedListener(onContextsChangedListener);

        extensionHook.addContextDataFactory(new ContextDataFactoryImpl());

        if (view != null) {
            extensionHook.getHookView().addContextPanelFactory(new ContextPanelFactoryImpl());
        }
    }

    /**
     * Gets the excluded elements of the given context.
     *
     * @param context the context.
     * @return the excluded elements.
     */
    public List<ExcludedElement> getExcludedElements(Context context) {
        Objects.requireNonNull(context);

        return getContextData(context).getExcludedElements();
    }

    /**
     * Sets the excluded elements for the given context.
     *
     * @param context the context.
     * @param excludedElements the excluded elements.
     */
    public void setExcludedElements(Context context, List<ExcludedElement> excludedElements) {
        Objects.requireNonNull(context);
        Objects.requireNonNull(excludedElements);

        getContextData(context).setExcludedElements(excludedElements);
    }

    public void unload() {
        Model.getSingleton().getSession().addOnContextsChangedListener(onContextsChangedListener);
    }

    private void discardContexts() {
        entries.clear();
    }

    private void discardContext(Context context) {
        entries.remove(context.getId());
    }

    private ContextData getContextData(Context context) {
        return entries.computeIfAbsent(context.getId(), e -> new ContextData(context));
    }

    /** The data of a context. */
    private class ContextData {

        private final Context ctx;
        private ContextPanel panel;

        private List<ExcludedElement> excludedElements;

        private ContextData(Context ctx) {
            this.ctx = ctx;
            this.excludedElements = List.of();
        }

        private ContextPanel getPanel() {
            if (panel == null) {
                panel = new ContextPanel(ctx.getId(), this, view);
            }
            return panel;
        }

        public List<ExcludedElement> getExcludedElements() {
            return excludedElements;
        }

        public void setExcludedElements(List<ExcludedElement> excludedElements) {
            setExcludedElementsNoPersistance(excludedElements);
            persistContextData();
        }

        private void setExcludedElementsNoPersistance(List<ExcludedElement> excludedElements) {
            this.excludedElements = Objects.requireNonNullElse(excludedElements, List.of());
        }

        void persistContextData() {
            try {
                List<String> data =
                        excludedElements.stream()
                                .map(ContextDataManager.this::encodeExcludedElement)
                                .collect(Collectors.toUnmodifiableList());
                model.getSession().setContextData(ctx.getId(), TYPE_EXCLUDED_ELEMENTS, data);
            } catch (Exception e) {
                LOGGER.error("An error occurred while persisting the data:", e);
            }
        }
    }

    @SuppressWarnings("serial")
    private static class ContextPanel extends AbstractContextPropertiesPanel {

        private static final long serialVersionUID = 1L;

        private static final String PANEL_NAME =
                Constant.messages.getString("spiderajax.context.panel.name");

        private final ContextData contextDataEntry;

        private final ExcludedElementsPanel excludedElementsPanel;

        public ContextPanel(int contextId, ContextData contextDataEntry, ViewDelegate view) {
            super(contextId);

            this.contextDataEntry = contextDataEntry;

            setLayout(new BorderLayout());
            setName(contextId + ": " + PANEL_NAME);

            excludedElementsPanel = new ExcludedElementsPanel(view.getSessionDialog(), true);
            add(excludedElementsPanel.getPanel());
        }

        @Override
        public String getHelpIndex() {
            return "addon.spiderajax.context";
        }

        @Override
        public void initContextData(Session session, Context uiSharedContext) {
            excludedElementsPanel.setElements(contextDataEntry.getExcludedElements());
        }

        @Override
        public void validateContextData(Session session) throws Exception {
            // Nothing to do.
        }

        @Override
        public void saveTemporaryContextData(Context uiSharedContext) {
            // Nothing to do.

        }

        @Override
        public void saveContextData(Session session) throws Exception {
            contextDataEntry.setExcludedElementsNoPersistance(excludedElementsPanel.getElements());
        }
    }

    private class ContextPanelFactoryImpl implements ContextPanelFactory {

        @Override
        public AbstractContextPropertiesPanel getContextPanel(Context ctx) {
            return getContextData(ctx).getPanel();
        }

        @Override
        public void discardContexts() {
            ContextDataManager.this.discardContexts();
        }

        @Override
        public void discardContext(Context ctx) {
            ContextDataManager.this.discardContext(ctx);
        }
    }

    private class ContextDataFactoryImpl implements ContextDataFactory {

        @Override
        public void loadContextData(Session session, Context context) {
            try {
                List<ExcludedElement> loaded =
                        session
                                .getContextDataStrings(context.getId(), TYPE_EXCLUDED_ELEMENTS)
                                .stream()
                                .map(this::decodeExcludedElement)
                                .filter(Objects::nonNull)
                                .collect(Collectors.toUnmodifiableList());
                getContextData(context).setExcludedElementsNoPersistance(loaded);
            } catch (Exception e) {
                LOGGER.error("An error occurred while loading the data:", e);
            }
        }

        private ExcludedElement decodeExcludedElement(String data) {
            String[] pieces = data.split(DATA_FIELD_SEPARATOR, -1);
            ExcludedElement excludedElement = null;
            try {
                excludedElement = new ExcludedElement();
                excludedElement.setEnabled(Boolean.parseBoolean(pieces[0]));
                excludedElement.setDescription(base64Decode(pieces[1]));
                excludedElement.setElement(base64Decode(pieces[2]));
                excludedElement.setXpath(base64Decode(pieces[3]));
                excludedElement.setText(base64Decode(pieces[4]));
                excludedElement.setAttributeName(base64Decode(pieces[5]));
                excludedElement.setAttributeValue(base64Decode(pieces[6]));
            } catch (Exception e) {
                LOGGER.error("An error occurred while decoding: {}", data, e);
            }
            return excludedElement;
        }

        @Override
        public void persistContextData(Session session, Context context) {
            getContextData(context).persistContextData();
        }

        @Override
        public void exportContextData(Context ctx, Configuration config) {
            getContextData(ctx).getExcludedElements().stream()
                    .map(ContextDataManager.this::encodeExcludedElement)
                    .forEach(e -> config.addProperty(CONFIG_EXCLUDED_ELEMENT, e));
        }

        @Override
        public void importContextData(Context ctx, Configuration config) {
            List<ExcludedElement> excludedElements =
                    config.getList(CONFIG_EXCLUDED_ELEMENT).stream()
                            .map(Object::toString)
                            .map(this::decodeExcludedElement)
                            .filter(Objects::nonNull)
                            .collect(Collectors.toList());
            getContextData(ctx).setExcludedElements(excludedElements);
        }
    }

    private static String base64Decode(String data) {
        if (data.isEmpty()) {
            return null;
        }
        return new String(Base64.getDecoder().decode(data), StandardCharsets.UTF_8);
    }

    private static String base64Encode(String data) {
        if (data == null) {
            return "";
        }
        return Base64.getEncoder().encodeToString(data.getBytes(StandardCharsets.UTF_8));
    }

    private String encodeExcludedElement(ExcludedElement excludedElement) {
        return new StringBuilder(100)
                .append(excludedElement.isEnabled())
                .append(DATA_FIELD_SEPARATOR)
                .append(base64Encode(excludedElement.getDescription()))
                .append(DATA_FIELD_SEPARATOR)
                .append(base64Encode(excludedElement.getElement()))
                .append(DATA_FIELD_SEPARATOR)
                .append(base64Encode(excludedElement.getXpath()))
                .append(DATA_FIELD_SEPARATOR)
                .append(base64Encode(excludedElement.getText()))
                .append(DATA_FIELD_SEPARATOR)
                .append(base64Encode(excludedElement.getAttributeName()))
                .append(DATA_FIELD_SEPARATOR)
                .append(base64Encode(excludedElement.getAttributeValue()))
                .append(DATA_FIELD_SEPARATOR)
                .toString();
    }

    private class OnContextsChangedListenerImpl implements OnContextsChangedListener {

        @Override
        public void contextAdded(Context context) {
            // Nothing to do.
        }

        @Override
        public void contextDeleted(Context context) {
            discardContext(context);
        }

        @Override
        public void contextsChanged() {
            // Nothing to do.
        }
    }

    private class SessionChangedListenerImpl implements SessionChangedListener {

        @Override
        public void sessionChanged(Session session) {
            // Nothing to do.
        }

        @Override
        public void sessionAboutToChange(Session session) {
            discardContexts();
        }

        @Override
        public void sessionScopeChanged(Session session) {
            // Nothing to do.
        }

        @Override
        public void sessionModeChanged(Mode mode) {
            // Nothing to do.
        }
    }
}
