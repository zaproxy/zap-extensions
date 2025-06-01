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
package org.zaproxy.addon.graphql.spider;

import org.apache.commons.httpclient.URI;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpSender;
import org.zaproxy.addon.graphql.GraphQlParser;
import org.zaproxy.addon.graphql.HistoryPersister;
import org.zaproxy.addon.graphql.MessageValidator;
import org.zaproxy.addon.spider.parser.ParseContext;
import org.zaproxy.addon.spider.parser.SpiderParser;

public class GraphQlSpider extends SpiderParser {

    private static final Logger LOGGER = LogManager.getLogger(GraphQlSpider.class);

    @Override
    public boolean parseResource(ParseContext ctx) {
        try {
            GraphQlParser parser =
                    new GraphQlParser(
                            ctx.getHttpMessage().getRequestHeader().getURI(),
                            HttpSender.SPIDER_INITIATOR,
                            false);
            parser.addRequesterListener(new HistoryPersister());
            parser.introspect(true);
        } catch (Exception e) {
            LOGGER.debug(e.getMessage(), e);
            return false;
        }
        return true;
    }

    @Override
    public boolean canParseResource(ParseContext ctx, boolean wasAlreadyConsumed) {
        HttpMessage message = ctx.getHttpMessage();
        URI uri = message.getRequestHeader().getURI();
        switch (MessageValidator.validate(message)) {
            case VALID_ENDPOINT:
                LOGGER.debug("Found GraphQL endpoint at: {}", uri);
                return true;
            case VALID_SCHEMA:
                LOGGER.debug("Found GraphQL schema at: {}", uri);
                break;
            default:
        }
        return false;
    }
}
