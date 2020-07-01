/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2020 The ZAP Development Team
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
package org.zaproxy.addon.graphql;

import net.htmlparser.jericho.Source;
import org.apache.log4j.Logger;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpSender;
import org.zaproxy.zap.spider.parser.SpiderParser;

public class GraphQlSpider extends SpiderParser {

    private static final Logger LOG = Logger.getLogger(GraphQlSpider.class);

    @Override
    public boolean parseResource(HttpMessage message, Source source, int depth) {
        try {
            GraphQlParser parser =
                    new GraphQlParser(
                            message.getRequestHeader().getURI(), HttpSender.SPIDER_INITIATOR);
            parser.addRequesterListener(new HistoryPersister());
            parser.introspect();
        } catch (Exception e) {
            LOG.debug(e.getMessage(), e);
            return false;
        }
        return true;
    }

    @Override
    public boolean canParseResource(HttpMessage message, String path, boolean wasAlreadyConsumed) {
        String uri = message.getRequestHeader().getURI().toString();
        switch (MessageValidator.validate(message)) {
            case VALID_ENDPOINT:
                LOG.debug("Found GraphQl endpoint at: " + uri);
                return true;
            case VALID_SCHEMA:
                LOG.debug("Found GraphQL schema at: " + uri);
                break;
        }
        return false;
    }
}
