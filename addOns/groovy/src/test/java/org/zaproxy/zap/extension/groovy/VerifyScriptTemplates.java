/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2018 The ZAP Development Team
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
package org.zaproxy.zap.extension.groovy;

import groovy.lang.GroovyClassLoader;
import java.io.IOException;
import java.nio.file.Path;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.zaproxy.zap.testutils.AbstractVerifyScriptTemplates;

/** Verifies that the Groovy templates are parsed without errors. */
public class VerifyScriptTemplates extends AbstractVerifyScriptTemplates {

    private static GroovyClassLoader groovyCl;

    @BeforeAll
    public static void setUp() {
        groovyCl = new GroovyClassLoader();
    }

    @AfterAll
    public static void teardown() throws IOException {
        groovyCl.close();
    }

    @Override
    protected String getScriptExtension() {
        return ".groovy";
    }

    @Override
    protected void parseTemplate(Path template) throws Exception {
        if (isExcluded(template)) {
            return;
        }
        groovyCl.parseClass(template.toFile());
    }

    private static boolean isExcluded(Path template) {
        String parentDir = template.getParent().getFileName().toString();
        // XXX Validate when the add-ons Fuzzer, Script Console, and encoder are included in the
        // test classpath.
        return parentDir.equals("httpfuzzerprocessor")
                || parentDir.equals("extender")
                || parentDir.equals("encode-decode");
    }
}
