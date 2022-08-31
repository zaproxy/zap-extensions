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
package org.zaproxy.zap.extension.openapi.spider;

import java.util.Locale;
import java.util.function.Supplier;
import org.apache.commons.lang.StringUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpSender;
import org.zaproxy.zap.extension.openapi.HistoryPersister;
import org.zaproxy.zap.extension.openapi.converter.Converter;
import org.zaproxy.zap.extension.openapi.converter.swagger.SwaggerConverter;
import org.zaproxy.zap.extension.openapi.network.Requestor;
import org.zaproxy.zap.model.ValueGenerator;

public class OpenApiSpiderFunctionality {

    private static final Logger LOGGER = LogManager.getLogger(OpenApiSpiderFunctionality.class);
    private Requestor requestor;
    private Supplier<ValueGenerator> valGenSupplier;

    public OpenApiSpiderFunctionality(Supplier<ValueGenerator> valueGeneratorSupplier) {
        valGenSupplier = valueGeneratorSupplier;
        requestor = new Requestor(HttpSender.SPIDER_INITIATOR);
        requestor.addListener(new HistoryPersister());
    }

    public boolean parseResource(HttpMessage message) {
        try {
            Converter converter =
                    new SwaggerConverter(
                            null,
                            message.getRequestHeader().getURI().toString(),
                            message.getResponseBody().toString(),
                            valGenSupplier.get());
            requestor.run(converter.getRequestModels());
        } catch (Exception e) {
            LOGGER.debug(e.getMessage(), e);
            return false;
        }

        return true;
    }

    public boolean canParseResource(HttpMessage message) {
        try {
            String contentType =
                    message.getResponseHeader()
                            .getHeader(HttpHeader.CONTENT_TYPE)
                            .toLowerCase(Locale.ROOT);
            String responseBodyStart =
                    StringUtils.left(message.getResponseBody().toString(), 250)
                            .toLowerCase(Locale.ROOT);
            if (contentType.startsWith("application/vnd.oai.openapi")
                    || (contentType.contains("json")
                            || contentType.contains("yaml")
                                    && (responseBodyStart.contains("swagger")
                                            || responseBodyStart.contains("openapi")))) {
                return true;
            }
        } catch (Exception e) {
            return false;
        }
        LOGGER.debug("Can't parse {}", message.getRequestHeader().getURI());
        return false;
    }
}
