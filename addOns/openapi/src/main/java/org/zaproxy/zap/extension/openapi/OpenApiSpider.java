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
package org.zaproxy.zap.extension.openapi;

import java.util.Locale;
import net.htmlparser.jericho.Source;
import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpSender;
import org.zaproxy.zap.extension.openapi.converter.Converter;
import org.zaproxy.zap.extension.openapi.converter.swagger.SwaggerConverter;
import org.zaproxy.zap.extension.openapi.network.Requestor;
import org.zaproxy.zap.extension.spider.ExtensionSpider;
import org.zaproxy.zap.model.ValueGenerator;
import org.zaproxy.zap.spider.parser.SpiderParser;

public class OpenApiSpider extends SpiderParser {

    private static final Logger log = Logger.getLogger(OpenApiSpider.class);
    private Requestor requestor;
    private ValueGenerator valGen = null;

    public OpenApiSpider() {
        requestor = new Requestor(HttpSender.SPIDER_INITIATOR);
        requestor.addListener(new HistoryPersister());
    }

    @Override
    public boolean parseResource(HttpMessage message, Source source, int depth) {
        try {
            Converter converter =
                    new SwaggerConverter(
                            null,
                            message.getRequestHeader().getURI().toString(),
                            message.getResponseBody().toString(),
                            this.getValueGenerator());
            requestor.run(converter.getRequestModels());
        } catch (Exception e) {
            log.debug(e.getMessage(), e);
            return false;
        }

        return true;
    }

    @Override
    public boolean canParseResource(HttpMessage message, String path, boolean wasAlreadyConsumed) {
        try {
            String contentType =
                    message.getResponseHeader()
                            .getHeader(HttpHeader.CONTENT_TYPE)
                            .toLowerCase(Locale.ROOT);
            String responseBodyStart =
                    StringUtils.left(message.getResponseBody().toString(), 250)
                            .toLowerCase(Locale.ROOT);
            if (contentType.startsWith("application/vnd.oai.openapi")) {
                return true;
            } else if ((contentType.contains("json") || contentType.contains("yaml"))
                    && (responseBodyStart.contains("swagger")
                            || responseBodyStart.contains("openapi"))) {
                return true;
            }
        } catch (Exception e) {
            return false;
        }
        log.debug("Cant parse " + message.getRequestHeader().getURI());
        return false;
    }

    private ValueGenerator getValueGenerator() {
        if (this.valGen == null) {
            ExtensionSpider spider =
                    Control.getSingleton().getExtensionLoader().getExtension(ExtensionSpider.class);
            valGen = spider.getValueGenerator();
        }
        return valGen;
    }
}
