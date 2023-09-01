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
import org.zaproxy.zap.model.DefaultValueGenerator;
import org.zaproxy.zap.model.ValueGenerator;

public class ExtensionCommonlib extends ExtensionAdaptor {

    private static final ValueGenerator DEFAULT_VALUE_GENERATOR = new DefaultValueGenerator();

    private ValueGenerator valueGeneratorImpl;

    private final ValueGenerator valueGeneratorWrapper =
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
                return DEFAULT_VALUE_GENERATOR.getValue(
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
     * @since 2.17.0
     */
    public ValueGenerator getValueGenerator() {
        return valueGeneratorWrapper;
    }

    /** <strong>Note:</strong> Not part of the public API. */
    public void setCustomValueGenerator(ValueGenerator generator) {
        this.valueGeneratorImpl = generator;
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
