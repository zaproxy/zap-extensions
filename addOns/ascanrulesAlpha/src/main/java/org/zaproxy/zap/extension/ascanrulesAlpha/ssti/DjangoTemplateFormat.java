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
package org.zaproxy.zap.extension.ascanrulesAlpha.ssti;

/**
 * This represents the code that is necessary to execute an arithmetic operation in Django template
 * engine and the expected result of the operation.
 *
 * @author DiogoMRSilva (2018)
 */
public class DjangoTemplateFormat extends TemplateFormat {

    public DjangoTemplateFormat() {
        super("{{", "}}", "{{%d0|add:%d0}}");
    }

    @Override
    public int getExpectedResult(int number1, int number2) {
        return number1 * 10 + number2 * 10;
    }
}
