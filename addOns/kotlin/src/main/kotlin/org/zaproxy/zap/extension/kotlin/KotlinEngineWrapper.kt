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

package org.zaproxy.zap.extension.kotlin

import org.fife.ui.rsyntaxtextarea.SyntaxConstants
import org.parosproxy.paros.Constant
import org.parosproxy.paros.extension.Extension
import org.zaproxy.zap.extension.script.DefaultEngineWrapper
import javax.script.ScriptEngine
import javax.script.ScriptEngineFactory
import javax.swing.ImageIcon

class KotlinEngineWrapper(scriptEngineFactory: ScriptEngineFactory): DefaultEngineWrapper(scriptEngineFactory) {

    override fun getExtensions(): MutableList<String> {
        return mutableListOf("kts")
    }

    override fun getIcon(): ImageIcon? {
        return ExtensionKotlin.KOTLIN_ICON
    }

    override fun getEngine(): ScriptEngine {
        return super.getEngine()
    }

    override fun getSyntaxStyle(): String {
        return SyntaxConstants.SYNTAX_STYLE_NONE
    }

    fun getAuthor(): String {
        return ExtensionKotlin.TEAM_NAME
    }

    fun getDescription(): String {
        return Constant.messages.getString("kotlin.desc")
    }

    fun getDependencies(): List<Class<out Extension>> {
        return ExtensionKotlin.EXTENSION_DEPENDENCIES
    }

    override fun isRawEngine(): Boolean {
        return false
    }
}