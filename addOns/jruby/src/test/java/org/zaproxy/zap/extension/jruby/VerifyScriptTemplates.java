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
package org.zaproxy.zap.extension.jruby;

import static org.junit.Assume.assumeTrue;

import java.io.Reader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import javax.script.Compilable;
import org.apache.commons.lang3.SystemUtils;
import org.jruby.embed.jsr223.JRubyEngineFactory;
import org.junit.BeforeClass;
import org.zaproxy.zap.testutils.AbstractVerifyScriptTemplates;

/** Verifies that the JRuby script templates are parsed without errors. */
public class VerifyScriptTemplates extends AbstractVerifyScriptTemplates {

    private static Compilable se;

    @BeforeClass
    public static void setUp() {
        // XXX Does not work with Java 9+, library is outdated.
        // Ref: https://github.com/zaproxy/zaproxy/issues/3944
        assumeTrue(SystemUtils.IS_JAVA_1_8);

        se = (Compilable) new JRubyEngineFactory().getScriptEngine();
    }

    @Override
    protected String getScriptExtension() {
        return ".rb";
    }

    @Override
    protected void parseTemplate(Path template) throws Exception {
        try (Reader reader = Files.newBufferedReader(template, StandardCharsets.UTF_8)) {
            se.compile(reader);
        }
    }
}
