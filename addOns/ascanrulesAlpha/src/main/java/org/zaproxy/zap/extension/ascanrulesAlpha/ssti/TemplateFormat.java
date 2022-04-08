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

import java.text.NumberFormat;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Random;

/**
 * This represents the code that is necessary to execute an arithmetic operation in a template
 * engine and the expected result of the operation.
 *
 * @author DiogoMRSilva (2018)
 */
public class TemplateFormat {
    private static final Random RAND = new Random();

    private final String startTag;
    private final String endTag;
    private final String mathOperationFormat;

    static final int MIN = 1111;
    static final int MAX = 9900;

    public TemplateFormat(String startTag, String endTag, String mathOperationFormat) {
        this.startTag = startTag;
        this.endTag = endTag;
        this.mathOperationFormat = mathOperationFormat;
    }

    public TemplateFormat(String startTag, String endTag) {
        this(startTag, endTag, startTag.replace("%", "%%") + "%d*%d" + endTag.replace("%", "%%"));
    }

    public String getStartTag() {
        return startTag;
    }

    public String getEndTag() {
        return endTag;
    }

    public int getExpectedResult(int number1, int number2) {
        return number1 * number2;
    }

    public List<String> getRenderTestAndResult() {

        ArrayList<String> values = new ArrayList<>();

        int number1 = RAND.nextInt((MAX - MIN) + 1) + MIN;
        int number2 = RAND.nextInt((MAX - MIN) + 1) + MIN;
        int operationResult = getExpectedResult(number1, number2);

        String exploit = String.format(this.mathOperationFormat, number1, number2);

        values.add(exploit);

        // 356435234
        values.add(Integer.toString(operationResult));
        // 356,435,234
        values.add(NumberFormat.getNumberInstance(Locale.US).format(operationResult));
        // 356.435.234
        values.add(NumberFormat.getNumberInstance(Locale.GERMANY).format(operationResult));

        return values;
    }
}
