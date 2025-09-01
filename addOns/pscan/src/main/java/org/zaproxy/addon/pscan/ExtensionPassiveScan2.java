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
package org.zaproxy.addon.pscan;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.SortedSet;
import java.util.TreeSet;
import java.util.stream.Collectors;
import javax.swing.ImageIcon;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.control.Control.Mode;
import org.parosproxy.paros.core.proxy.ProxyListener;
import org.parosproxy.paros.extension.Extension;
import org.parosproxy.paros.extension.ExtensionAdaptor;
import org.parosproxy.paros.extension.ExtensionHook;
import org.parosproxy.paros.extension.ExtensionLoader;
import org.parosproxy.paros.extension.SessionChangedListener;
import org.parosproxy.paros.extension.history.ExtensionHistory;
import org.parosproxy.paros.extension.history.ProxyListenerLog;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.model.Session;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.addon.pscan.internal.AddOnScanRulesLoader;
import org.zaproxy.addon.pscan.internal.DefaultStatsListener;
import org.zaproxy.addon.pscan.internal.PassiveScannerOptions;
import org.zaproxy.addon.pscan.internal.RegexAutoTagScanner;
import org.zaproxy.addon.pscan.internal.ScanRuleManager;
import org.zaproxy.addon.pscan.internal.StatsPassiveScanner;
import org.zaproxy.addon.pscan.internal.scanner.PassiveScanController;
import org.zaproxy.addon.pscan.internal.scanner.PassiveScanTask;
import org.zaproxy.addon.pscan.internal.ui.OptionsPassiveScan;
import org.zaproxy.addon.pscan.internal.ui.PassiveScannerOptionsPanel;
import org.zaproxy.addon.pscan.internal.ui.PolicyPassiveScanPanel;
import org.zaproxy.zap.extension.alert.ExtensionAlert;
import org.zaproxy.zap.extension.pscan.PassiveController;
import org.zaproxy.zap.extension.pscan.PassiveScanRuleManager;
import org.zaproxy.zap.extension.pscan.PassiveScanner;
import org.zaproxy.zap.extension.pscan.PluginPassiveScanner;
import org.zaproxy.zap.extension.script.ExtensionScript;
import org.zaproxy.zap.extension.script.ScriptType;
import org.zaproxy.zap.utils.DisplayUtils;
import org.zaproxy.zap.utils.Stats;
import org.zaproxy.zap.utils.StatsListener;
import org.zaproxy.zap.view.ScanStatus;

public class ExtensionPassiveScan2 extends ExtensionAdaptor {

    public static final String NAME = "ExtensionPassiveScan2";

    // Should be after the last one that saves the HttpMessage, as this ProxyListener doesn't change
    // the HttpMessage.
    public static final int PROXY_LISTENER_ORDER = ProxyListenerLog.PROXY_LISTENER_ORDER + 1;

    public static final String SCRIPT_TYPE_PASSIVE = "passive";

    private static final Logger LOGGER = LogManager.getLogger(ExtensionPassiveScan2.class);

    private static final List<Class<? extends Extension>> DEPENDENCIES =
            List.of(
                    ExtensionAlert.class,
                    org.zaproxy.zap.extension.pscan.ExtensionPassiveScan.class);

    private AddOnScanRulesLoader scanRulesLoader;

    private ScanStatus scanStatus;
    private StatsListener statsListener;

    private ScriptType scriptType;

    private OptionsPassiveScan optionsPassiveScan;
    private PolicyPassiveScanPanel policyPanel;
    private PassiveScannerOptions options;
    private PassiveScannerOptionsPanel passiveScannerOptionsPanel;

    private PassiveScannersManagerImpl scannersManager;
    private PassiveScanRuleManager scanRuleManagerProxy;
    private PassiveController passiveControllerProxy;

    private PassiveScanController psc;
    private boolean passiveScanEnabled;

    private List<PassiveScanRuleProvider> pscanRuleProviders =
            Collections.synchronizedList(new ArrayList<>());

    public ExtensionPassiveScan2() {
        super(NAME);

        scannersManager = new PassiveScannersManagerImpl();
        scanRuleManagerProxy =
                new PassiveScanRuleManager() {

                    @Override
                    public boolean add(PassiveScanner scanRule) {
                        return scannersManager.add(scanRule);
                    }

                    @Override
                    public PassiveScanner getScanRule(int id) {
                        return scannersManager.getScanRule(id);
                    }

                    @Override
                    public List<PassiveScanner> getScanRules() {
                        return scannersManager.getScanners();
                    }

                    @Override
                    public List<PluginPassiveScanner> getPluginScanRules() {
                        return scannersManager.getScanRules();
                    }

                    @Override
                    public boolean remove(String className) {
                        return scannersManager.removeImpl(className);
                    }

                    @Override
                    public boolean remove(PassiveScanner scanRule) {
                        return scannersManager.removeImpl(scanRule);
                    }
                };

        passiveControllerProxy =
                new PassiveController() {

                    @Override
                    public int getRecordsToScan() {
                        return ExtensionPassiveScan2.this.getRecordsToScan();
                    }

                    @Override
                    public void clearQueue() {
                        ExtensionPassiveScan2.this.clearQueue();
                    }
                };
    }

    private void setScanRuleManager(PassiveScanRuleManager manager) {
        getExtPscan().setPassiveScanRuleManager(manager);
    }

    private void setPassiveController(PassiveController controller) {
        getExtPscan().setPassiveController(controller);
    }

    @Override
    public List<Class<? extends Extension>> getDependencies() {
        return DEPENDENCIES;
    }

    @Override
    public String getUIName() {
        return Constant.messages.getString("pscan.ext.name");
    }

    @Override
    public String getDescription() {
        return Constant.messages.getString("pscan.ext.desc");
    }

    @Override
    public void init() {
        options = new PassiveScannerOptions();

        setScanRuleManager(scanRuleManagerProxy);
        setPassiveController(passiveControllerProxy);

        scanRulesLoader = new AddOnScanRulesLoader(this);
    }

    @Override
    public void postInit() {
        scanRulesLoader.load();

        StatsPassiveScanner.load(this);
    }

    @Override
    public void optionsLoaded() {
        scannersManager.getManager().setAutoTagScanners(options.getAutoTagScanners());

        passiveScanEnabled = true;
        getPassiveScanController();
    }

    /**
     * Gets the tags used for auto tagging.
     *
     * @return a sorted set with the tags, never {@code null}.
     * @since 0.2.0
     */
    public SortedSet<String> getAutoTaggingTags() {
        return options.getAutoTagScanners().stream()
                .map(RegexAutoTagScanner::getConf)
                .collect(Collectors.toCollection(TreeSet<String>::new));
    }

    /**
     * Gets the manager of passive scanners.
     *
     * @return the manager, never {@code null}.
     * @since 0.1.0
     */
    public PassiveScannersManager getPassiveScannersManager() {
        return scannersManager;
    }

    /**
     * Gets the number of records to scan (queued).
     *
     * @return the number of records to scan.
     * @since 0.1.0
     */
    public int getRecordsToScan() {
        if (passiveScanEnabled && psc != null) {
            return psc.getRecordsToScan();
        }
        return 0;
    }

    /**
     * Empties the passive scanner queue without passively scanning the messages.
     *
     * <p>Currently running scanners will run to completion but new scanners will only be run when
     * new messages are added to the queue.
     *
     * @since 0.1.0
     */
    public void clearQueue() {
        if (psc != null) {
            psc.clearQueue();
        }
    }

    private PassiveScanController getPassiveScanController() {
        if (passiveScanEnabled && psc == null) {
            ExtensionLoader extensionLoader = Control.getSingleton().getExtensionLoader();
            psc =
                    new PassiveScanController(
                            this,
                            extensionLoader.getExtension(ExtensionHistory.class),
                            extensionLoader.getExtension(ExtensionAlert.class));
            psc.setSession(Model.getSingleton().getSession());
            psc.start();
        }
        return psc;
    }

    @Override
    public void hook(ExtensionHook extensionHook) {
        extensionHook.addOptionsParamSet(options);

        if (hasView()) {
            extensionHook.getHookView().addOptionPanel(getPassiveScannerOptionsPanel());
            extensionHook.getHookView().addOptionPanel(getOptionsPassiveScan());
            extensionHook.getHookView().addOptionPanel(getPolicyPanel());
        }

        extensionHook.addApiImplementor(new PassiveScanApi(this, scannersManager));

        extensionHook.addAddOnInstallationStatusListener(scanRulesLoader);

        if (hasView()) {
            scanStatus =
                    new ScanStatus(
                            DisplayUtils.getScaledIcon(getClass().getResource("icons/pscan.png")),
                            Constant.messages.getString("pscan.footer.label"));
            statsListener =
                    new DefaultStatsListener() {

                        @Override
                        public void highwaterMarkSet(String key, long value) {
                            if ("stats.pscan.recordsToScan".equals(key)) {
                                scanStatus.setScanCount((int) value);
                            }
                        }
                    };
            Stats.addListener(statsListener);

            getView()
                    .getMainFrame()
                    .getMainFooterPanel()
                    .addFooterToolbarRightLabel(scanStatus.getCountLabel());
        }

        ExtensionScript extScript = getExtension(ExtensionScript.class);
        if (extScript != null) {
            scriptType =
                    new ScriptType(
                            SCRIPT_TYPE_PASSIVE,
                            "pscan.scripts.type.passive",
                            createScriptIcon(),
                            true);
            extScript.registerScriptType(scriptType);
        }

        extensionHook.addProxyListener(new ProxyListenerImpl());
        extensionHook.addSessionListener(new SessionListenerImpl());
    }

    private PolicyPassiveScanPanel getPolicyPanel() {
        if (policyPanel == null) {
            policyPanel = new PolicyPassiveScanPanel();
        }
        return policyPanel;
    }

    private PassiveScannerOptionsPanel getPassiveScannerOptionsPanel() {
        if (passiveScannerOptionsPanel == null) {
            passiveScannerOptionsPanel =
                    new PassiveScannerOptionsPanel(this::clearQueue, Constant.messages);
        }
        return passiveScannerOptionsPanel;
    }

    private OptionsPassiveScan getOptionsPassiveScan() {
        if (optionsPassiveScan == null) {
            optionsPassiveScan = new OptionsPassiveScan(scannersManager.getManager());
        }
        return optionsPassiveScan;
    }

    private ImageIcon createScriptIcon() {
        if (!hasView()) {
            return null;
        }
        return DisplayUtils.getScaledIcon(getClass().getResource("icons/script-pscan.png"));
    }

    private static org.zaproxy.zap.extension.pscan.ExtensionPassiveScan getExtPscan() {
        return getExtension(org.zaproxy.zap.extension.pscan.ExtensionPassiveScan.class);
    }

    private static <T extends Extension> T getExtension(Class<T> clazz) {
        return Control.getSingleton().getExtensionLoader().getExtension(clazz);
    }

    @Override
    public boolean canUnload() {
        return true;
    }

    @Override
    public void unload() {
        scanRulesLoader.unload();

        if (hasView()) {
            getView()
                    .getMainFrame()
                    .getMainFooterPanel()
                    .removeFooterToolbarRightLabel(scanStatus.getCountLabel());

            Stats.removeListener(statsListener);
        }

        if (scriptType != null) {
            getExtension(ExtensionScript.class).removeScriptType(scriptType);
        }

        setScanRuleManager(null);
        setPassiveController(null);
    }

    @Override
    public void destroy() {
        super.destroy();

        stopPassiveScanController();
    }

    private void stopPassiveScanController() {
        if (psc != null) {
            psc.shutdown();
            psc = null;
        }
    }

    void setPassiveScanEnabled(boolean enabled) {
        if (passiveScanEnabled != enabled) {
            passiveScanEnabled = enabled;
            if (enabled) {
                getPassiveScanController();
            } else {
                stopPassiveScanController();
            }
        }
    }

    PassiveScanTask getOldestRunningTask() {
        if (passiveScanEnabled) {
            return getPassiveScanController().getOldestRunningTask();
        }
        return null;
    }

    List<PassiveScanTask> getRunningTasks() {
        if (passiveScanEnabled) {
            return getPassiveScanController().getRunningTasks();
        }
        return List.of();
    }

    /**
     * @since 0.4.0
     */
    public List<PassiveScanRuleProvider> getPscanRuleProviders() {
        return pscanRuleProviders;
    }

    /**
     * @since 0.4.0
     */
    public void addPscanRuleProvider(PassiveScanRuleProvider provider) {
        pscanRuleProviders.add(provider);
    }

    /**
     * @since 0.4.0
     */
    public void removePscanRuleProvider(PassiveScanRuleProvider provider) {
        pscanRuleProviders.remove(provider);
    }

    private class ProxyListenerImpl implements ProxyListener {

        @Override
        public int getArrangeableListenerOrder() {
            return PROXY_LISTENER_ORDER;
        }

        @Override
        public boolean onHttpRequestSend(HttpMessage msg) {
            return true;
        }

        @Override
        public boolean onHttpResponseReceive(HttpMessage msg) {
            if (psc != null) {
                psc.responseReceived();
            }
            return true;
        }
    }

    private class SessionListenerImpl implements SessionChangedListener {

        @Override
        public void sessionAboutToChange(Session session) {
            stopPassiveScanController();
        }

        @Override
        public void sessionChanged(Session session) {
            if (passiveScanEnabled) {
                getPassiveScanController().setSession(session);
            }
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

    private class PassiveScannersManagerImpl implements PassiveScannersManager {

        private final ScanRuleManager scanRuleManager;

        PassiveScannersManagerImpl() {
            this.scanRuleManager = new ScanRuleManager();
        }

        ScanRuleManager getManager() {
            return scanRuleManager;
        }

        @Override
        public boolean add(PassiveScanner scanner) {
            try {
                boolean added = scanRuleManager.add(scanner);
                if (added && scanner instanceof PluginPassiveScanner) {
                    PluginPassiveScanner pps = (PluginPassiveScanner) scanner;
                    pps.setConfig(getModel().getOptionsParam().getConfig());
                    if (hasView()) {
                        getPolicyPanel().getPassiveScanTableModel().addScanner(pps);
                    }
                }
                return added;

            } catch (Exception e) {
                LOGGER.error("Failed to load passive scan rule {}", scanner.getName(), e);
                return false;
            }
        }

        @Override
        public boolean remove(PassiveScanner scanner) {
            return removeImpl(scanner);
        }

        public boolean removeImpl(Object value) {
            boolean removed;
            PassiveScanner scanner;
            if (value instanceof PassiveScanner) {
                scanner = (PassiveScanner) value;
                removed = scanRuleManager.remove(scanner);
            } else {
                String name = (String) value;
                scanner = scanRuleManager.getScanRule(name);
                removed = scanRuleManager.remove(name);
            }

            if (scanner != null && hasView() && scanner instanceof PluginPassiveScanner) {
                getPolicyPanel()
                        .getPassiveScanTableModel()
                        .removeScanner((PluginPassiveScanner) scanner);
            }

            return removed;
        }

        @Override
        public List<PassiveScanner> getScanners() {
            return scanRuleManager.getScanners();
        }

        @Override
        public PluginPassiveScanner getScanRule(int id) {
            return scanRuleManager.getScanRule(id);
        }

        @Override
        public List<PluginPassiveScanner> getScanRules() {
            return scanRuleManager.getScanRules();
        }
    }
}
