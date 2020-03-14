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
package org.zaproxy.zap.extension.openapi.generators;

public class Element {

    public enum Json {
        OBJECT_BEGIN("{"),
        OBJECT_END("}"),
        ARRAY_BEGIN("["),
        ARRAY_END("]"),
        PROPERTY_CONTAINER("\""),
        INNER_SEPARATOR(":"),
        OUTER_SEPARATOR(",");

        private String syntax;

        Json(String syntax) {
            this.syntax = syntax;
        }

        @Override
        public String toString() {
            return syntax;
        }
    }

    public enum OpenApiType {
        STRING("string");

        private String type;

        OpenApiType(String type) {
            this.type = type;
        }

        public String type() {
            return this.type;
        }
    }

    public enum Form {
        INNER_SEPARATOR(":"),
        OUTER_SEPARATOR(",");

        private String syntax;

        Form(String syntax) {
            this.syntax = syntax;
        }

        @Override
        public String toString() {
            return syntax;
        }
    }
}
