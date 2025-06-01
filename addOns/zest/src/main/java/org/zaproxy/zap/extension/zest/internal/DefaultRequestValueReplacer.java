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
package org.zaproxy.zap.extension.zest.internal;

import java.io.IOException;
import java.sql.SQLException;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import lombok.AllArgsConstructor;
import lombok.Getter;
import net.htmlparser.jericho.Element;
import net.htmlparser.jericho.HTMLElementName;
import net.htmlparser.jericho.Source;
import org.apache.commons.httpclient.URI;
import org.apache.commons.lang3.StringUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.model.Session;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.zest.ZestParam;
import org.zaproxy.zap.extension.zest.ZestZapUtils;
import org.zaproxy.zap.model.DefaultNameValuePair;
import org.zaproxy.zap.model.NameValuePair;
import org.zaproxy.zap.model.ParameterParser;
import org.zaproxy.zest.core.v1.ZestAssignFieldValue;
import org.zaproxy.zest.core.v1.ZestFieldDefinition;
import org.zaproxy.zest.core.v1.ZestRequest;
import org.zaproxy.zest.core.v1.ZestScript;

public class DefaultRequestValueReplacer implements RequestValueReplacer {

    private static final Logger LOGGER = LogManager.getLogger(DefaultRequestValueReplacer.class);

    private final Session session;
    private final Map<String, Map<String, ValueSource>> values;

    private int messageCount;
    private String rawUrl;

    public DefaultRequestValueReplacer(Session session) {
        this.session = session;
        values = new HashMap<>();
    }

    @Override
    public ZestRequest process(ZestScript script, HttpMessage message, ZestParam conversionOptions)
            throws IOException, SQLException {
        replaceValues(script, message);
        extractVariables(script, message);

        ZestRequest request = ZestZapUtils.toZestRequest(message, false, true, conversionOptions);
        if (rawUrl != null) {
            request.setUrl(null);
            request.setUrlToken(rawUrl);

            rawUrl = null;
        }
        return request;
    }

    private void replaceValues(ZestScript script, HttpMessage message) {
        if (values.isEmpty()) {
            return;
        }

        Set<ValueSource> usedValues = new HashSet<>();
        String url = message.getRequestHeader().getURI().toString();
        replaceQueryValues(session.getUrlParamParser(url), message, usedValues);
        replaceBodyValues(session.getFormParamParser(url), message, usedValues);

        usedValues.forEach(
                e -> {
                    ZestFieldDefinition fd = new ZestFieldDefinition();
                    fd.setFormIndex(e.getFormIndex());
                    fd.setFieldName(e.getName());

                    ZestAssignFieldValue fv = new ZestAssignFieldValue();
                    fv.setVariableName(e.getVarName());
                    fv.setFieldDefinition(fd);

                    script.add(fv);
                });
    }

    private void replaceQueryValues(
            ParameterParser parser, HttpMessage message, Set<ValueSource> usedValues) {
        URI uri = message.getRequestHeader().getURI();
        List<NameValuePair> parameters = parser.parseRawParameters(uri.getEscapedQuery());
        if (parameters.isEmpty()) {
            return;
        }

        String result = replaceValues(usedValues, parser, parameters);

        try {
            URI replacedUri = (URI) uri.clone();
            replacedUri.setEscapedQuery(null);
            rawUrl = replacedUri.toString() + "?" + result;
        } catch (Exception e) {
            LOGGER.error("An error occurred while creating the URI:", e);
        }
    }

    private String replaceValues(
            Set<ValueSource> usedValues, ParameterParser parser, List<NameValuePair> parameters) {
        for (int i = 0; i < parameters.size(); i++) {
            NameValuePair nvp = parameters.get(i);
            Map<String, ValueSource> sources = values.get(nvp.getValue());
            if (sources != null) {
                String name = nvp.getName();
                ValueSource source = sources.get(name);
                if (source != null) {
                    parameters.set(i, new DefaultNameValuePair(name, source.getVarToken()));
                    usedValues.add(source);
                }
            }
        }

        return toString(parser, parameters);
    }

    private static String toString(ParameterParser parser, List<NameValuePair> parameters) {
        StringBuilder data = new StringBuilder();

        for (NameValuePair parameter : parameters) {
            if (data.length() > 0) {
                data.append(parser.getDefaultKeyValuePairSeparator());
            }

            data.append(parameter.getName());
            data.append(parser.getDefaultKeyValueSeparator());
            data.append(parameter.getValue());
        }

        return data.toString();
    }

    private void replaceBodyValues(
            ParameterParser parser, HttpMessage message, Set<ValueSource> usedValues) {
        List<NameValuePair> parameters =
                parser.parseRawParameters(message.getRequestBody().toString());
        if (parameters.isEmpty()) {
            return;
        }

        String result = replaceValues(usedValues, parser, parameters);

        message.setRequestBody(result);
    }

    private void extractVariables(ZestScript sz, HttpMessage message) {
        messageCount++;
        values.clear();

        List<Element> formElements =
                new Source(message.getResponseBody().toString())
                        .getAllElements(HTMLElementName.FORM);
        if (formElements.isEmpty()) {
            return;
        }

        for (int formIndex = 0; formIndex < formElements.size(); formIndex++) {
            Element formElement = formElements.get(formIndex);
            List<Element> inputElements = formElement.getAllElements(HTMLElementName.INPUT);
            if (inputElements.isEmpty()) {
                continue;
            }

            for (Element inputElement : inputElements) {
                String value = inputElement.getAttributeValue("VALUE");
                if (StringUtils.isEmpty(value)) {
                    continue;
                }

                String name = inputElement.getAttributeValue("NAME");
                if (!StringUtils.isBlank(name)) {
                    String varName = "Msg" + messageCount + "Form" + formIndex + "Field" + name;
                    String varToken =
                            sz.getParameters().getTokenStart()
                                    + varName
                                    + sz.getParameters().getTokenEnd();
                    values.computeIfAbsent(value, e -> new HashMap<>())
                            .put(name, new ValueSource(varName, varToken, formIndex, name, value));
                }
            }
        }
    }

    @Getter
    @AllArgsConstructor
    private static class ValueSource {

        private final String varName;
        private final String varToken;
        private final int formIndex;
        private final String name;
        private final String value;
    }
}
