/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2019 The ZAP Development Team
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
package org.zaproxy.zap.extension.quickstart.hud;

import java.lang.reflect.Method;
import java.util.List;
import org.apache.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.extension.Extension;
import org.parosproxy.paros.extension.ExtensionAdaptor;
import org.parosproxy.paros.extension.ExtensionHook;
import org.zaproxy.zap.extension.quickstart.ExtensionQuickStart;
import org.zaproxy.zap.extension.quickstart.PlugableHud;

/**
 * Provides the option to use the HUD when exploring via the quick start tab. This is a separate
 * extension so that the main extension still loads if the HUD is not installed.
 */
public class ExtensionQuickStartHud extends ExtensionAdaptor implements PlugableHud {

    public static final String NAME = "ExtensionQuickStartHud";
    private static final Logger LOGGER = Logger.getLogger(ExtensionQuickStartHud.class);

    private static final String EXTENSION_HUD_CLASSNAME =
            "org.zaproxy.zap.extension.hud.ExtensionHUD";

    private Method isEnabledMethod;

    public ExtensionQuickStartHud() {
        super(NAME);
    }

    @Override
    public boolean supportsDb(String type) {
        return true;
    }

    @Override
    public void hook(ExtensionHook extensionHook) {
        super.hook(extensionHook);

        if (getView() != null) {
            this.getExtQuickStart().setHudProvider(this);
        }
    }

    @Override
    public boolean isHudEnabled() {
        try {
            if (isEnabledMethod == null) {
                isEnabledMethod = getExtHudClass().getMethod("isHudEnabled");
            }
            if (isEnabledMethod != null) {
                Object res = isEnabledMethod.invoke(ExtensionQuickStartHud.getExtHud());
                if (res instanceof Boolean) {
                    return ((Boolean) res).booleanValue();
                }
            }
        } catch (Exception e) {
            LOGGER.error(e.getMessage(), e);
        }
        return false;
    }

    @Override
    public void setHudEnabledForDesktop(boolean enabled) {
        try {
            Method methodSetEnabled =
                    getExtHudClass().getMethod("setHudEnabledForDesktop", Boolean.class);
            methodSetEnabled.invoke(ExtensionQuickStartHud.getExtHud(), enabled);
        } catch (Exception e) {
            LOGGER.error(e.getMessage(), e);
        }
    }

    @Override
    public boolean isInScopeOnly() {
        try {
            Method methodGetHudParam = getExtHudClass().getMethod("getHudParam");
            Object hudParam = methodGetHudParam.invoke(ExtensionQuickStartHud.getExtHud());
            if (hudParam != null) {
                Method methodIsInScopeOnly = hudParam.getClass().getMethod("isInScopeOnly");
                return (boolean) methodIsInScopeOnly.invoke(hudParam);
            }
        } catch (Exception e) {
            LOGGER.error(e.getMessage(), e);
        }
        return false;
    }

    @Override
    public boolean canUnload() {
        return true;
    }

    @Override
    public void unload() {
        if (getView() != null) {
            this.getExtQuickStart().setHudProvider(null);
        }
    }

    @Override
    public String getDescription() {
        return Constant.messages.getString("quickstart.launch.desc");
    }

    @Override
    public String getUIName() {
        return Constant.messages.getString("quickstart.launch.name");
    }

    public ExtensionQuickStart getExtQuickStart() {
        return Control.getSingleton().getExtensionLoader().getExtension(ExtensionQuickStart.class);
    }

    @SuppressWarnings("unchecked")
    public static Class<Extension> getExtHudClass() {
        try {
            return (Class<Extension>) Class.forName(EXTENSION_HUD_CLASSNAME);
        } catch (ClassNotFoundException e) {
            LOGGER.error(e.getMessage(), e);
        }
        return null;
    }

    public static Extension getExtHud() {
        return Control.getSingleton()
                .getExtensionLoader()
                .getExtensionByClassName(EXTENSION_HUD_CLASSNAME);
    }

    @Override
    @SuppressWarnings("unchecked")
    public List<String> getSupportedBrowserIds() {
        try {
            Method method =
                    ExtensionQuickStartHud.getExtHud()
                            .getClass()
                            .getMethod("getSupportedBrowserIds");
            return (List<String>) method.invoke(ExtensionQuickStartHud.getExtHud());
        } catch (Exception e) {
            LOGGER.error(e.getMessage(), e);
        }
        return null;
    }
}
