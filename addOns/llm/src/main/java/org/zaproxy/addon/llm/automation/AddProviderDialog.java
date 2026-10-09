/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2026 The ZAP Development Team
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
package org.zaproxy.addon.llm.automation;

import java.util.ArrayList;
import java.util.List;
import java.util.function.Function;
import java.util.stream.Stream;
import org.apache.commons.lang3.StringUtils;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.view.View;
import org.zaproxy.addon.llm.LlmProvider;
import org.zaproxy.addon.llm.automation.LlmConfigJob.Provider;
import org.zaproxy.zap.utils.DisplayUtils;
import org.zaproxy.zap.view.StandardFieldsDialog;

/** A dialog to add or modify a provider of an {@link LlmConfigJob}. */
@SuppressWarnings("serial")
class AddProviderDialog extends StandardFieldsDialog {

    private static final long serialVersionUID = 1L;

    private static final String TITLE = "llm.configjob.dialog.provider.title";
    private static final String NAME_PARAM = "llm.configjob.dialog.provider.name";
    private static final String TYPE_PARAM = "llm.configjob.dialog.provider.type";
    private static final String API_KEY_PARAM = "llm.configjob.dialog.provider.apikey";
    private static final String ENDPOINT_PARAM = "llm.configjob.dialog.provider.endpoint";
    private static final String MODELS_PARAM = "llm.configjob.dialog.provider.models";
    private static final String TRUSTED_PARAM = "llm.configjob.dialog.provider.trusted";
    private static final String TIMEOUT_PARAM = "llm.configjob.dialog.provider.timeout";

    private final LlmProviderTableModel model;
    private final int tableIndex;
    private final Function<Provider, String> validator;

    /**
     * @param provider the provider to modify, or {@code null} to add a new one
     * @param tableIndex the index of the provider in the model, ignored if adding
     * @param validator validates a provider, returning the problem found or {@code null}
     */
    AddProviderDialog(
            LlmProviderTableModel model,
            Provider provider,
            int tableIndex,
            Function<Provider, String> validator) {
        super(View.getSingleton().getMainFrame(), TITLE, DisplayUtils.getScaledDimension(500, 400));
        this.model = model;
        this.tableIndex = provider == null ? -1 : tableIndex;
        this.validator = validator;

        Provider p = provider != null ? provider : new Provider();
        addTextField(NAME_PARAM, p.getName());
        addComboField(
                TYPE_PARAM,
                Stream.concat(
                                Stream.of(""),
                                Stream.of(LlmProvider.values())
                                        .filter(t -> t != LlmProvider.NONE)
                                        .map(LlmProvider::toString))
                        .toList(),
                p.getType() != null ? p.getType().toString() : "");
        addPasswordField(API_KEY_PARAM, p.getApiKey());
        addTextField(ENDPOINT_PARAM, p.getEndpoint());
        addMultilineField(
                MODELS_PARAM, p.getModels() != null ? String.join("\n", p.getModels()) : "");
        addCheckBoxField(
                TRUSTED_PARAM,
                p.getTrusted() != null
                        ? p.getTrusted()
                        : p.getType() != null && p.getType().isTrustedByDefault());
        addNumberField(
                TIMEOUT_PARAM, 0, Integer.MAX_VALUE, p.getTimeout() != null ? p.getTimeout() : 0);
        addPadding();
    }

    private Provider toProvider() {
        Provider provider = new Provider();
        provider.setName(StringUtils.trimToNull(getStringValue(NAME_PARAM)));
        provider.setType(toType(getStringValue(TYPE_PARAM)));
        provider.setApiKey(StringUtils.trimToNull(getStringValue(API_KEY_PARAM)));
        provider.setEndpoint(StringUtils.trimToNull(getStringValue(ENDPOINT_PARAM)));
        provider.setModels(toModels(getStringValue(MODELS_PARAM)));
        provider.setTrusted(getBoolValue(TRUSTED_PARAM));
        int timeout = getIntValue(TIMEOUT_PARAM);
        provider.setTimeout(timeout > 0 ? timeout : null);
        return provider;
    }

    static LlmProvider toType(String displayName) {
        return Stream.of(LlmProvider.values())
                .filter(t -> t.toString().equals(displayName))
                .findFirst()
                .orElse(null);
    }

    static List<String> toModels(String text) {
        List<String> models =
                new ArrayList<>(text.lines().map(String::trim).filter(l -> !l.isEmpty()).toList());
        return models.isEmpty() ? null : models;
    }

    @Override
    public void save() {
        Provider provider = toProvider();
        if (tableIndex < 0) {
            model.add(provider);
        } else {
            model.update(tableIndex, provider);
        }
    }

    @Override
    public String validateFields() {
        Provider provider = toProvider();
        if (model.isNameUsed(provider.getName(), tableIndex)) {
            return Constant.messages.getString("llm.configjob.error.duplicate", provider.getName());
        }
        return validator.apply(provider);
    }
}
