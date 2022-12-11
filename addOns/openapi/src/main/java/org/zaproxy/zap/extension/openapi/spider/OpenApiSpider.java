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
import org.apache.commons.lang3.StringUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpSender;
import org.zaproxy.addon.spider.parser.ParseContext;
import org.zaproxy.addon.spider.parser.SpiderParser;
import org.zaproxy.zap.extension.openapi.HistoryPersister;
import org.zaproxy.zap.extension.openapi.converter.Converter;
import org.zaproxy.zap.extension.openapi.converter.swagger.SwaggerConverter;
import org.zaproxy.zap.extension.openapi.network.Requestor;
import org.zaproxy.zap.model.ValueGenerator;

public class OpenApiSpider extends SpiderParser {

    private static final Logger LOGGER = LogManager.getLogger(OpenApiSpider.class);
    private Requestor requestor;
    private Supplier<ValueGenerator> valGenSupplier;

    public OpenApiSpider(Supplier<ValueGenerator> valueGeneratorSupplier) {
        valGenSupplier = valueGeneratorSupplier;
        requestor = new Requestor(HttpSender.SPIDER_INITIATOR);
        requestor.addListener(new HistoryPersister());
    }

    @Override
    public boolean parseResource(ParseContext ctx) {
        HttpMessage message = ctx.getHttpMessage();
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

    @Override
    public boolean canParseResource(ParseContext ctx, boolean wasAlreadyConsumed) {
        HttpMessage message = ctx.getHttpMessage();
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
