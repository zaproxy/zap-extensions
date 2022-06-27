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
package org.zaproxy.addon.spider.internal;

import org.zaproxy.addon.spider.parser.SpiderParserListener;
import org.zaproxy.addon.spider.parser.SpiderResourceFound;

public class Adapters {

    public static SpiderParserListener coreToAddOn(
            org.zaproxy.zap.spider.parser.SpiderParserListener listener) {
        return new CoreToAddOnListener(listener);
    }

    public static org.zaproxy.zap.spider.parser.SpiderResourceFound addOnToCore(
            SpiderResourceFound resourceFound) {
        return org.zaproxy.zap.spider.parser.SpiderResourceFound.builder()
                .setBody(resourceFound.getBody())
                .setDepth(resourceFound.getDepth())
                .setHeaders(resourceFound.getHeaders())
                .setMessage(resourceFound.getMessage())
                .setMethod(resourceFound.getMethod())
                .setShouldIgnore(resourceFound.isShouldIgnore())
                .setUri(resourceFound.getUri())
                .build();
    }

    public static SpiderResourceFound coreToAddOn(
            org.zaproxy.zap.spider.parser.SpiderResourceFound resourceFound) {
        return SpiderResourceFound.builder()
                .setBody(resourceFound.getBody())
                .setDepth(resourceFound.getDepth())
                .setHeaders(resourceFound.getHeaders())
                .setMessage(resourceFound.getMessage())
                .setMethod(resourceFound.getMethod())
                .setShouldIgnore(resourceFound.isShouldIgnore())
                .setUri(resourceFound.getUri())
                .build();
    }

    private static class CoreToAddOnListener implements SpiderParserListener {

        private final org.zaproxy.zap.spider.parser.SpiderParserListener listener;

        CoreToAddOnListener(org.zaproxy.zap.spider.parser.SpiderParserListener listener) {
            this.listener = listener;
        }

        @Override
        public void resourceFound(SpiderResourceFound resourceFound) {
            listener.resourceFound(addOnToCore(resourceFound));
        }

        @Override
        public int hashCode() {
            return listener.hashCode();
        }

        @Override
        public boolean equals(Object obj) {
            if (!(obj instanceof CoreToAddOnListener)) {
                return false;
            }
            return listener.equals(((CoreToAddOnListener) obj).listener);
        }
    }
}
