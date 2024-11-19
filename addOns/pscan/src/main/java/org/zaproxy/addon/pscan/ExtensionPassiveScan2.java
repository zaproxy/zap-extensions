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

import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.util.List;
import javax.swing.ImageIcon;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.extension.Extension;
import org.parosproxy.paros.extension.ExtensionAdaptor;
import org.parosproxy.paros.extension.ExtensionHook;
import org.zaproxy.addon.pscan.internal.AddOnScanRulesLoader;
import org.zaproxy.addon.pscan.internal.DefaultStatsListener;
import org.zaproxy.addon.pscan.internal.ScanRuleManager;
import org.zaproxy.addon.pscan.internal.StatsPassiveScanner;
import org.zaproxy.addon.pscan.internal.ui.OptionsPassiveScan;
import org.zaproxy.addon.pscan.internal.ui.PassiveScannerOptionsPanel;
import org.zaproxy.addon.pscan.internal.ui.PolicyPassiveScanPanel;
import org.zaproxy.zap.extension.pscan.PassiveScanParam;
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

    public static final String SCRIPT_TYPE_PASSIVE = "passive";

    private static final Logger LOGGER = LogManager.getLogger(ExtensionPassiveScan2.class);

    private static final List<Class<? extends Extension>> DEPENDENCIES =
            List.of(org.zaproxy.zap.extension.pscan.ExtensionPassiveScan.class);

    private final boolean loadScanRules;
    private AddOnScanRulesLoader scanRulesLoader;

    private boolean addScanStatus;
    private ScanStatus scanStatus;
    private StatsListener statsListener;

    private final boolean addScriptType;
    private ScriptType scriptType;

    private final boolean addOptions;

    private OptionsPassiveScan optionsPassiveScan;
    private PolicyPassiveScanPanel policyPanel;
    private PassiveScanParam passiveScanParam;
    private PassiveScannerOptionsPanel passiveScannerOptionsPanel;

    private Method setPassiveScanRuleManager;
    private ScanRuleManager scanRuleManager;
    private Object scanRuleManagerProxy;

    public ExtensionPassiveScan2() {
        super(NAME);

        loadScanRules =
                !hasField(
                        org.zaproxy.zap.extension.pscan.ExtensionPassiveScan.class,
                        "addOnScanRules");

        addScriptType =
                isFieldDeprecated(
                        org.zaproxy.zap.extension.pscan.ExtensionPassiveScan.class,
                        "SCRIPT_TYPE_PASSIVE");

        addOptions =
                hasField(
                        org.zaproxy.zap.extension.pscan.ExtensionPassiveScan.class,
                        "scanRuleManager");

        if (addOptions) {
            try {
                scanRuleManager = new ScanRuleManager();
                InvocationHandler invocationHandler =
                        (o, method, args) -> {
                            switch (method.getName()) {
                                case "add":
                                    {
                                        PassiveScanner scanner = (PassiveScanner) args[0];
                                        try {
                                            boolean added = scanRuleManager.add(scanner);
                                            if (added
                                                    && hasView()
                                                    && scanner instanceof PluginPassiveScanner) {
                                                PluginPassiveScanner pps =
                                                        (PluginPassiveScanner) scanner;
                                                pps.setConfig(
                                                        getModel().getOptionsParam().getConfig());
                                                getPolicyPanel()
                                                        .getPassiveScanTableModel()
                                                        .addScanner(pps);
                                            }
                                            return added;

                                        } catch (Exception e) {
                                            LOGGER.error(
                                                    "Failed to load passive scan rule {}",
                                                    scanner.getName(),
                                                    e);
                                            return false;
                                        }
                                    }
                                case "getScanRule":
                                    return scanRuleManager.getScanRule((int) args[0]);

                                case "getScanRules":
                                    return scanRuleManager.getScanRules();

                                case "getPluginScanRules":
                                    return scanRuleManager.getPluginScanRules();

                                case "remove":
                                    {
                                        boolean removed;
                                        PassiveScanner scanner;
                                        if (args[0] instanceof PassiveScanner) {
                                            scanner = (PassiveScanner) args[0];
                                            removed = scanRuleManager.remove(scanner);
                                        } else {
                                            String name = (String) args[0];
                                            scanner = scanRuleManager.getScanRule(name);
                                            removed = scanRuleManager.remove(name);
                                        }

                                        if (scanner != null
                                                && hasView()
                                                && scanner instanceof PluginPassiveScanner) {
                                            getPolicyPanel()
                                                    .getPassiveScanTableModel()
                                                    .removeScanner((PluginPassiveScanner) scanner);
                                        }

                                        return removed;
                                    }

                                default:
                                    return null;
                            }
                        };

                Class<?> clazz =
                        org.zaproxy.zap.extension.pscan.ExtensionPassiveScan.class
                                .getClassLoader()
                                .loadClass(
                                        "org.zaproxy.zap.extension.pscan.PassiveScanRuleManager");
                setPassiveScanRuleManager =
                        org.zaproxy.zap.extension.pscan.ExtensionPassiveScan.class
                                .getDeclaredMethod("setPassiveScanRuleManager", clazz);
                scanRuleManagerProxy =
                        Proxy.newProxyInstance(
                                clazz.getClassLoader(), new Class<?>[] {clazz}, invocationHandler);

            } catch (Exception e) {
                LOGGER.error("Failed to create ScanRuleManager:", e);
            }
        }
    }

    private void setScanRuleManager(Object object) {
        try {
            setPassiveScanRuleManager.invoke(getExtPscan(), object);
        } catch (Exception e) {
            LOGGER.error("Failed to set ScanRuleManager:", e);
        }
    }

    private static boolean isFieldDeprecated(Class<?> clazz, String name) {
        try {
            return clazz.getField(name).getAnnotation(Deprecated.class) != null;
        } catch (NoSuchFieldException e) {
            // Nothing to do.
        }
        return true;
    }

    private static boolean hasField(Class<?> clazz, String name) {
        try {
            clazz.getDeclaredField(name);
            return true;
        } catch (NoSuchFieldException e) {
            // Nothing to do.
        }
        return false;
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
        if (scanRuleManager != null) {
            setScanRuleManager(scanRuleManagerProxy);
        }

        if (loadScanRules) {
            scanRulesLoader = new AddOnScanRulesLoader(getExtPscan());
        }

        addScanStatus =
                hasView()
                        && !hasField(
                                org.zaproxy.zap.extension.pscan.ExtensionPassiveScan.class,
                                "scanStatus");
    }

    @Override
    public void postInit() {
        if (loadScanRules) {
            scanRulesLoader.load();
        }
        StatsPassiveScanner.load(getExtPscan());
    }

    @Override
    public void optionsLoaded() {
        if (scanRuleManager != null) {
            scanRuleManager.setAutoTagScanners(getPassiveScanParam().getAutoTagScanners());
        }
    }

    @Override
    public void hook(ExtensionHook extensionHook) {
        if (scanRuleManager != null) {
            extensionHook.addOptionsParamSet(getPassiveScanParam());

            if (hasView()) {
                extensionHook.getHookView().addOptionPanel(getPassiveScannerOptionsPanel());
                extensionHook.getHookView().addOptionPanel(getOptionsPassiveScan());
                extensionHook.getHookView().addOptionPanel(getPolicyPanel());
            }
        }

        if (org.zaproxy.zap.extension.pscan.PassiveScanAPI.class.getAnnotation(Deprecated.class)
                != null) {
            extensionHook.addApiImplementor(new PassiveScanApi(getExtPscan()));
        }

        if (loadScanRules) {
            extensionHook.addAddOnInstallationStatusListener(scanRulesLoader);
        }

        if (addScanStatus) {
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

        if (addScriptType) {
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
        }
    }

    private PolicyPassiveScanPanel getPolicyPanel() {
        if (policyPanel == null) {
            policyPanel = new PolicyPassiveScanPanel();
        }
        return policyPanel;
    }

    private PassiveScanParam getPassiveScanParam() {
        if (passiveScanParam == null) {
            passiveScanParam = new PassiveScanParam();
        }
        return passiveScanParam;
    }

    private PassiveScannerOptionsPanel getPassiveScannerOptionsPanel() {
        if (passiveScannerOptionsPanel == null) {
            passiveScannerOptionsPanel =
                    new PassiveScannerOptionsPanel(getExtPscan(), Constant.messages);
        }
        return passiveScannerOptionsPanel;
    }

    private OptionsPassiveScan getOptionsPassiveScan() {
        if (optionsPassiveScan == null) {
            optionsPassiveScan = new OptionsPassiveScan(scanRuleManager);
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
        if (loadScanRules) {
            scanRulesLoader.unload();
        }
        StatsPassiveScanner.unload(getExtPscan());

        if (addScanStatus) {
            getView()
                    .getMainFrame()
                    .getMainFooterPanel()
                    .removeFooterToolbarRightLabel(scanStatus.getCountLabel());

            Stats.removeListener(statsListener);
        }

        if (scriptType != null) {
            getExtension(ExtensionScript.class).removeScriptType(scriptType);
        }

        if (addOptions) {
            setScanRuleManager(null);
        }
    }
}
