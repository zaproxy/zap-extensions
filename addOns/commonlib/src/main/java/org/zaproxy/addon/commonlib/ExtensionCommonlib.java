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
import javax.swing.JButton;
import org.apache.commons.httpclient.URI;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control.Mode;
import org.parosproxy.paros.extension.ExtensionAdaptor;
import org.parosproxy.paros.extension.ExtensionHook;
import org.parosproxy.paros.extension.SessionChangedListener;
import org.parosproxy.paros.model.Session;
import org.zaproxy.addon.commonlib.gspm.GspmRegistry;
import org.zaproxy.addon.commonlib.gspm.GspmRuleSource;
import org.zaproxy.addon.commonlib.gspm.internal.GspmActiveScanRegistrar;
import org.zaproxy.addon.commonlib.gspm.internal.GspmPolicyManagerDialog;
import org.zaproxy.addon.commonlib.internal.vulns.LegacyVulnerabilities;
import org.zaproxy.addon.commonlib.ui.GenerateFixPromptMenu;
import org.zaproxy.addon.commonlib.ui.PopupMenuTreeTools;
import org.zaproxy.addon.commonlib.ui.ProgressPanel;
import org.zaproxy.addon.commonlib.ui.SitesTreeInfoMenu;
import org.zaproxy.addon.commonlib.ui.TabbedOutputPanel;
import org.zaproxy.zap.utils.DisplayUtils;
import org.zaproxy.zap.view.ZapMenuItem;

public class ExtensionCommonlib extends ExtensionAdaptor {

    private static final Logger LOGGER = LogManager.getLogger(ExtensionCommonlib.class);

    private static final ValueProvider DEFAULT_VALUE_PROVIDER = new DefaultValueProvider();

    private final GspmRegistry gspmRegistry = new GspmRegistry();
    private final GspmActiveScanRegistrar gspmAscanRegistrar = new GspmActiveScanRegistrar();
    private GspmPolicyManagerDialog gspmPolicyManagerDialog;
    private ZapMenuItem menuItemGspm;
    private JButton gspmButton;

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
        CommonlibParam commonlibParam = new CommonlibParam();
        extensionHook.addOptionsParamSet(commonlibParam);

        if (hasView()) {
            extensionHook.getHookView().addStatusPanel(getProgressPanel());
            getView().setOutputPanel(new TabbedOutputPanel());
            extensionHook.getHookMenu().addPopupMenuItem(new GenerateFixPromptMenu(commonlibParam));
            extensionHook.getHookMenu().addPopupMenuItem(new SitesTreeInfoMenu());
            extensionHook.getHookMenu().addPopupMenuItem(new PopupMenuTreeTools());
            if (Constant.isDevBuild()) {
                extensionHook.getHookMenu().addAnalyseMenuItem(getMenuItemGspm());
                extensionHook.getHookView().addMainToolBarComponent(getGspmButton());
            }
        }
        extensionHook.addSessionListener(new SessionChangedListenerImpl());
    }

    @Override
    public void postInit() {
        if (Constant.isDevBuild()) {
            gspmRegistry.loadPolicies(Constant.getPoliciesDir());
        }
        gspmAscanRegistrar.registerWithCore(gspmRegistry);
    }

    /**
     * Registers a {@link GspmRuleSource} with the GSPM registry, immediately invoking {@link
     * GspmRuleSource#registerRulesWithGspm(GspmRegistry)}.
     *
     * <p>Add-ons should call this from their {@code postInit()} once their rules are loaded, and
     * call {@link #unregisterGspmRuleSource(GspmRuleSource)} from their {@code unload()}.
     *
     * <p>This is WIP and will be changed to add support for dynamically added rules.
     *
     * @since 1.39.0
     */
    public void registerGspmRuleSource(GspmRuleSource source) {
        source.registerRulesWithGspm(gspmRegistry);
    }

    /**
     * Unregisters a previously registered {@link GspmRuleSource}, invoking {@link
     * GspmRuleSource#unregisterRulesFromGspm(GspmRegistry)}.
     *
     * @since 1.39.0
     */
    public void unregisterGspmRuleSource(GspmRuleSource source) {
        source.unregisterRulesFromGspm(gspmRegistry);
    }

    /**
     * Returns the Global Scan Policy Manager registry.
     *
     * @return the GSPM registry, never {@code null}.
     * @since 1.39.0
     */
    public GspmRegistry getGspmRegistry() {
        return gspmRegistry;
    }

    private ZapMenuItem getMenuItemGspm() {
        if (menuItemGspm == null) {
            menuItemGspm = new ZapMenuItem("commonlib.gspm.menu.analyse");
            menuItemGspm.addActionListener(e -> showGspmPolicyManagerDialog());
        }
        return menuItemGspm;
    }

    private JButton getGspmButton() {
        if (gspmButton == null) {
            gspmButton = new JButton();
            gspmButton.setIcon(
                    DisplayUtils.getScaledIcon(
                            ExtensionCommonlib.class.getResource(
                                    "/resource/icon/fugue/equalizer.png")));
            gspmButton.setToolTipText(Constant.messages.getString("commonlib.gspm.menu.analyse"));
            gspmButton.addActionListener(e -> showGspmPolicyManagerDialog());
        }
        return gspmButton;
    }

    private void showGspmPolicyManagerDialog() {
        if (gspmPolicyManagerDialog == null) {
            gspmPolicyManagerDialog =
                    new GspmPolicyManagerDialog(getView().getMainFrame(), gspmRegistry);
        }
        gspmPolicyManagerDialog.setVisible(true);
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
        gspmAscanRegistrar.unregisterFromCore();
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
