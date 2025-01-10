/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2017 The ZAP Development Team
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
package org.zaproxy.zap.extension.formhandler;

import java.util.List;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.extension.Extension;
import org.parosproxy.paros.extension.ExtensionAdaptor;
import org.parosproxy.paros.extension.ExtensionHook;
import org.parosproxy.paros.extension.ExtensionLoader;
import org.zaproxy.addon.commonlib.ExtensionCommonlib;
import org.zaproxy.addon.commonlib.ValueProvider;
import org.zaproxy.zap.extension.params.ExtensionParams;
import org.zaproxy.zap.model.DefaultValueGenerator;
import org.zaproxy.zap.model.ValueGenerator;
import org.zaproxy.zap.utils.Stats;

public class ExtensionFormHandler extends ExtensionAdaptor {

    public static final String NAME = "ExtensionFormHandler";

    private static final List<Class<? extends Extension>> DEPENDENCIES =
            List.of(ExtensionCommonlib.class);

    private static final String STATS_PREFIX = "stats.formhandler.";
    public static final String STATS_ADD = ExtensionFormHandler.STATS_PREFIX + "add";
    public static final String STATS_MODIFY = ExtensionFormHandler.STATS_PREFIX + "modify";
    public static final String STATS_REMOVE = ExtensionFormHandler.STATS_PREFIX + "remove";

    protected static final String PREFIX = "formhandler";

    private FormHandlerParam param;
    private ValueProvider valueProvider;

    private OptionsFormHandlerPanel optionsFormHandlerPanel;
    private PopupMenuAddFormhandlerParam popupMenuAddFormhandlerParam;

    public ExtensionFormHandler() {
        super(NAME);
    }

    @Override
    public List<Class<? extends Extension>> getDependencies() {
        return DEPENDENCIES;
    }

    /**
     * Gets the value generator, with user provided values.
     *
     * @return the value generator.
     * @since 6.0.0
     * @deprecated (6.7.0) Use {@link ExtensionCommonlib#getValueProvider()}.
     */
    @SuppressWarnings("removal")
    @Deprecated(since = "6.7.0", forRemoval = true)
    public ValueGenerator getValueGenerator() {
        return new DefaultValueGenerator();
    }

    @Override
    public void init() {
        valueProvider = new FormHandlerValueProvider(getParam());
    }

    @Override
    public void hook(ExtensionHook extensionHook) {
        super.hook(extensionHook);

        extensionHook.addOptionsParamSet(getParam());
        ExtensionLoader extLoader = Control.getSingleton().getExtensionLoader();

        if (hasView()) {
            extensionHook.getHookView().addOptionPanel(getOptionsFormHandlerPanel());
            if (extLoader.isExtensionEnabled(ExtensionParams.NAME)) {
                extensionHook.getHookMenu().addPopupMenuItem(getPopupMenuAddFormhandlerParam());
            }
        }

        setCustomValueProvider(valueProvider);
    }

    private static void setCustomValueProvider(ValueProvider valueProvider) {
        getExtension(ExtensionCommonlib.class).setCustomValueProvider(valueProvider);
    }

    @Override
    public boolean canUnload() {
        return true;
    }

    private static <T extends Extension> T getExtension(Class<T> clazz) {
        return Control.getSingleton().getExtensionLoader().getExtension(clazz);
    }

    @Override
    public void unload() {
        setCustomValueProvider(null);
    }

    // Method for creating and obtaining the Options Panel
    private OptionsFormHandlerPanel getOptionsFormHandlerPanel() {
        if (optionsFormHandlerPanel == null) {
            optionsFormHandlerPanel = new OptionsFormHandlerPanel();
        }
        return optionsFormHandlerPanel;
    }

    protected FormHandlerParam getParam() {
        if (param == null) {
            param = new FormHandlerParam();
        }
        return param;
    }

    public List<String> getFormHandlerFieldNames() {
        return this.getParam().getEnabledFieldsNames();
    }

    public void addFormHandlerFieldName(String field, String value) {
        this.getParam().addField(field, value);
    }

    public void removeFormHandlerFieldName(String field) {
        this.getParam().removeField(field);
    }

    private PopupMenuAddFormhandlerParam getPopupMenuAddFormhandlerParam() {
        if (popupMenuAddFormhandlerParam == null) {
            popupMenuAddFormhandlerParam = new PopupMenuAddFormhandlerParam();
        }
        return popupMenuAddFormhandlerParam;
    }

    @Override
    public String getDescription() {
        return Constant.messages.getString(PREFIX + ".options.desc");
    }

    static void incStat(String stat, String name) {
        Stats.incCounter(stat);
        Stats.incCounter(stat + "." + name);
    }

    static void incStat(String stat, FormHandlerParamField field) {
        incStat(stat, field.getName());
    }
}
