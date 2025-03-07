/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2022 The ZAP Development Team
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
package org.zaproxy.addon.commonlib;

import java.util.List;
import java.util.Map;
import org.apache.commons.httpclient.URI;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control.Mode;
import org.parosproxy.paros.extension.ExtensionAdaptor;
import org.parosproxy.paros.extension.ExtensionHook;
import org.parosproxy.paros.extension.SessionChangedListener;
import org.parosproxy.paros.model.Session;
import org.zaproxy.addon.commonlib.internal.vulns.LegacyVulnerabilities;
import org.zaproxy.addon.commonlib.ui.ProgressPanel;
import org.zaproxy.addon.commonlib.ui.TabbedOutputPanel;

public class ExtensionCommonlib extends ExtensionAdaptor {

    private static final ValueProvider DEFAULT_VALUE_PROVIDER = new DefaultValueProvider();

    @SuppressWarnings("removal")
    private org.zaproxy.zap.model.ValueGenerator valueGeneratorImpl;

    @SuppressWarnings({"removal", "deprecation"})
    private final org.zaproxy.zap.model.ValueGenerator valueGeneratorWrapper =
            (URI uri,
                    String url,
                    String fieldId,
                    String defaultValue,
                    List<String> definedValues,
                    Map<String, String> envAttributes,
                    Map<String, String> fieldAttributes) -> {
                var local = valueGeneratorImpl;
                if (local != null) {
                    return local.getValue(
                            uri,
                            url,
                            fieldId,
                            defaultValue,
                            definedValues,
                            envAttributes,
                            fieldAttributes);
                }
                return DEFAULT_VALUE_PROVIDER.getValue(
                        uri,
                        url,
                        fieldId,
                        defaultValue,
                        definedValues,
                        envAttributes,
                        fieldAttributes);
            };

    private ValueProvider valueProviderImpl;

    private final ValueProvider valueProviderWrapper =
            (URI uri,
                    String url,
                    String fieldId,
                    String defaultValue,
                    List<String> definedValues,
                    Map<String, String> envAttributes,
                    Map<String, String> fieldAttributes) -> {
                var local = valueProviderImpl;
                if (local != null) {
                    return local.getValue(
                            uri,
                            url,
                            fieldId,
                            defaultValue,
                            definedValues,
                            envAttributes,
                            fieldAttributes);
                }
                return DEFAULT_VALUE_PROVIDER.getValue(
                        uri,
                        url,
                        fieldId,
                        defaultValue,
                        definedValues,
                        envAttributes,
                        fieldAttributes);
            };

    private ProgressPanel progressPanel;

    public ExtensionCommonlib() {
        LegacyVulnerabilities.load();
    }

    @Override
    public void hook(ExtensionHook extensionHook) {
        if (hasView()) {
            extensionHook.getHookView().addStatusPanel(getProgressPanel());
            getView().setOutputPanel(new TabbedOutputPanel());
        }
        extensionHook.addSessionListener(new SessionChangedListenerImpl());
    }

    public ProgressPanel getProgressPanel() {
        if (progressPanel == null) {
            progressPanel = new ProgressPanel(getView());
        }
        return progressPanel;
    }

    @Override
    public boolean canUnload() {
        return true;
    }

    @Override
    public void unload() {
        if (hasView()) {
            getView().setOutputPanel(null);
        }
        LegacyVulnerabilities.unload();
    }

    @Override
    public boolean supportsDb(String type) {
        return true;
    }

    @Override
    public String getDescription() {
        return Constant.messages.getString("commonlib.desc");
    }

    @Override
    public String getUIName() {
        return Constant.messages.getString("commonlib.name");
    }

    /**
     * Gets the value generator.
     *
     * @return the value generator, never {@code null}.
     * @since 1.17.0
     * @deprecated (1.29.0) Use {@link #getValueProvider()} instead, to stop using core interface.
     */
    @SuppressWarnings("removal")
    @Deprecated(since = "1.29.0", forRemoval = true)
    public org.zaproxy.zap.model.ValueGenerator getValueGenerator() {
        return valueGeneratorWrapper;
    }

    /**
     * Gets the value generator.
     *
     * @return the value generator, never {@code null}.
     * @since 1.29.0
     */
    public ValueProvider getValueProvider() {
        return valueProviderWrapper;
    }

    /** <strong>Note:</strong> Not part of the public API. */
    @Deprecated(forRemoval = true)
    @SuppressWarnings("removal")
    public void setCustomValueGenerator(org.zaproxy.zap.model.ValueGenerator generator) {
        this.valueGeneratorImpl = generator;
    }

    /** <strong>Note:</strong> Not part of the public API. */
    public void setCustomValueProvider(ValueProvider provider) {
        this.valueProviderImpl = provider;
    }

    private class SessionChangedListenerImpl implements SessionChangedListener {

        @Override
        public void sessionChanged(Session session) {
            // Nothing to do
        }

        @Override
        public void sessionAboutToChange(Session session) {
            if (hasView()) {
                getProgressPanel().clearAndDispose();
            }
            SourceSinkUtils.reset();
        }

        @Override
        public void sessionScopeChanged(Session session) {
            // Nothing to do
        }

        @Override
        public void sessionModeChanged(Mode mode) {
            // Nothing to do
        }
    }
}
