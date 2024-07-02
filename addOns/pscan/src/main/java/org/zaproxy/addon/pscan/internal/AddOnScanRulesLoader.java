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
package org.zaproxy.addon.pscan.internal;

import java.lang.reflect.Constructor;
import java.lang.reflect.Modifier;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.apache.commons.lang3.StringUtils;
import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.zaproxy.zap.control.AddOn;
import org.zaproxy.zap.control.AddOn.InstallationStatus;
import org.zaproxy.zap.control.ExtensionFactory;
import org.zaproxy.zap.extension.AddOnInstallationStatusListener;
import org.zaproxy.zap.extension.AddOnInstallationStatusListener.StatusUpdate;
import org.zaproxy.zap.extension.pscan.ExtensionPassiveScan;
import org.zaproxy.zap.extension.pscan.PluginPassiveScanner;

public class AddOnScanRulesLoader implements AddOnInstallationStatusListener {

    private static final Logger LOGGER = LogManager.getLogger(AddOnScanRulesLoader.class);

    private final Map<AddOn, List<PluginPassiveScanner>> addOnScanRules;
    private final ExtensionPassiveScan extension;

    public AddOnScanRulesLoader(ExtensionPassiveScan extension) {
        addOnScanRules = new HashMap<>();
        this.extension = extension;
    }

    public void load() {
        ExtensionFactory.getAddOnLoader().getAddOnCollection().getAddOns().stream()
                .filter(addOn -> addOn.getInstallationStatus() == InstallationStatus.INSTALLED)
                .forEach(this::loadScanRules);
    }

    public void unload() {
        addOnScanRules.keySet().forEach(this::removeScanRules);
        addOnScanRules.clear();
    }

    @Override
    public void update(StatusUpdate statusUpdate) {
        switch (statusUpdate.getStatus()) {
            case INSTALLED:
                loadScanRules(statusUpdate.getAddOn());
                break;

            case SOFT_UNINSTALL:
            case UNINSTALL:
                AddOn addOn = statusUpdate.getAddOn();
                removeScanRules(addOn);
                addOnScanRules.remove(addOn);
                break;

            default:
        }
    }

    private void removeScanRules(AddOn addOn) {
        List<PluginPassiveScanner> loadedPscanrules = addOnScanRules.get(addOn);
        if (loadedPscanrules != null && !loadedPscanrules.isEmpty()) {
            LOGGER.debug("Uninstall pscanrules: {}", addOn.getPscanrules());

            for (PluginPassiveScanner pscanrule : loadedPscanrules) {
                String name = pscanrule.getClass().getCanonicalName();
                LOGGER.debug("Uninstall pscanrule: {}", name);
                if (!extension.removePassiveScanner(pscanrule)) {
                    LOGGER.error("Failed to uninstall pscanrule: {}", name);
                }
            }
        }
    }

    private List<PluginPassiveScanner> getPassiveScanRules(AddOn addOn) {
        validateNotNull(addOn, "addOn");

        synchronized (addOnScanRules) {
            return addOnScanRules.computeIfAbsent(
                    addOn,
                    aO ->
                            loadDeclaredClasses(
                                    aO.getClassLoader(),
                                    aO.getPscanrules(),
                                    PluginPassiveScanner.class,
                                    "pscanrule"));
        }
    }

    private void loadScanRules(AddOn addOn) {
        List<PluginPassiveScanner> pscanrules = getPassiveScanRules(addOn);
        if (!pscanrules.isEmpty()) {
            for (PluginPassiveScanner pscanrule : pscanrules) {
                validateName(pscanrule);
                pscanrule.setStatus(addOn.getStatus());
                String name = pscanrule.getClass().getCanonicalName();
                LOGGER.debug("Install pscanrule: {}", name);
                if (!extension.addPassiveScanner(pscanrule)) {
                    LOGGER.error("Failed to install pscanrule: {}", name);
                }
            }
        }
    }

    private static void validateName(PluginPassiveScanner rule) {
        if (StringUtils.isBlank(rule.getName())) {
            LOGGER.log(
                    Constant.isDevBuild() ? Level.ERROR : Level.WARN,
                    "Scan rule {} does not have a name.",
                    rule.getClass().getCanonicalName());
        }
    }

    private static <T> List<T> loadDeclaredClasses(
            ClassLoader addOnClassLoader, List<String> classnames, Class<T> clazz, String type) {
        validateNotNull(addOnClassLoader, "addOnClassLoader");
        validateNotNull(classnames, "classnames");
        validateNotNull(clazz, "clazz");
        validateNotNull(type, "type");

        if (classnames.isEmpty()) {
            return Collections.emptyList();
        }

        ArrayList<T> instances = new ArrayList<>(classnames.size());
        for (String classname : classnames) {
            T instance = loadAndInstantiateClassImpl(addOnClassLoader, classname, clazz, type);
            if (instance != null) {
                instances.add(instance);
            }
        }
        instances.trimToSize();
        return Collections.unmodifiableList(instances);
    }

    private static <T> T loadAndInstantiateClassImpl(
            ClassLoader addOnClassLoader, String classname, Class<T> clazz, String type) {
        Class<?> cls;
        try {
            cls = addOnClassLoader.loadClass(classname);
        } catch (ClassNotFoundException e) {
            LOGGER.error("Declared \"{}\" was not found: {}", type, classname, e);
            return null;
        } catch (LinkageError e) {
            LOGGER.error("Declared \"{}\" could not be loaded: {}", type, classname, e);
            return null;
        }

        if (Modifier.isAbstract(cls.getModifiers()) || Modifier.isInterface(cls.getModifiers())) {
            LOGGER.error("Declared \"{}\" is abstract or an interface: {}", type, classname);
            return null;
        }

        if (!clazz.isAssignableFrom(cls)) {
            LOGGER.error(
                    "Declared \"{}\" is not of type \"{}\": {}", type, clazz.getName(), classname);
            return null;
        }

        try {
            @SuppressWarnings("unchecked")
            Constructor<T> c = (Constructor<T>) cls.getConstructor();
            return c.newInstance();
        } catch (LinkageError | Exception e) {
            LOGGER.error("Failed to initialise: {}", classname, e);
        }
        return null;
    }

    private static void validateNotNull(Object object, String name) {
        if (object == null) {
            throw new IllegalArgumentException("Parameter " + name + " must not be null.");
        }
    }
}
