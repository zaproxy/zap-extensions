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
package org.zaproxy.zap.extension.kotlin;

import java.util.Collections;
import java.util.List;
import javax.script.ScriptEngineFactory;
import javax.swing.*;
import org.fife.ui.rsyntaxtextarea.SyntaxConstants;
import org.zaproxy.zap.extension.script.DefaultEngineWrapper;

public class KotlinEngineWrapper extends DefaultEngineWrapper {

    @Override
    public ImageIcon getIcon() {
        return ExtensionKotlin.KOTLIN_ICON;
    }

    @Override
    public String getSyntaxStyle() {
        return SyntaxConstants.SYNTAX_STYLE_NONE;
    }

    @Override
    public boolean isRawEngine() {
        return false;
    }

    @Override
    public List<String> getExtensions() {
        return Collections.singletonList("kts");
    }

    public KotlinEngineWrapper(ScriptEngineFactory factory) {
        super(factory);
    }
}
