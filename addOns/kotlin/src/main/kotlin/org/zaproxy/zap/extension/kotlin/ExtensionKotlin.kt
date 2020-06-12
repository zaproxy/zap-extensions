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

import org.apache.log4j.Logger
import org.parosproxy.paros.control.Control
import org.parosproxy.paros.extension.Extension
import org.parosproxy.paros.extension.ExtensionAdaptor
import org.parosproxy.paros.extension.ExtensionHook
import org.parosproxy.paros.view.View
import org.zaproxy.zap.ZAP
import org.zaproxy.zap.control.ExtensionFactory
import org.zaproxy.zap.extension.script.ExtensionScript
import javax.swing.ImageIcon

class ExtensionKotlin : ExtensionAdaptor(NAME) {


    companion object {
        val NAME = "ExtensionKotlin"
        val TEAM_NAME = "StackHawk Engineering"
        val KOTLIN_ICON: ImageIcon? = if (View.isInitialised()) ImageIcon(
                ExtensionKotlin::class.java.getResource(
                        "/org/zaproxy/zap/extension/kotlin/resources/kotlin.png")) else null

        val EXTENSION_DEPENDENCIES: List<Class<out Extension>> = listOf(ExtensionScript::class.java)
        private val LOGGER: Logger = Logger.getLogger(ExtensionKotlin::class.java)
    }

    init {
        order = 9999

    }

    override fun hook(extensionHook: ExtensionHook?) {
        super.hook(extensionHook)

        LOGGER.info("Hooking Kotlin Scripting Extension")

        val zapJar = ZAP::class.java.protectionDomain.codeSource.location.file

        LOGGER.info("Loading Kotlin engine...")
        val cl = ExtensionFactory.getAddOnLoader()
        cl.urLs.forEach { LOGGER.info(it) }
        extScript
                .registerScriptEngineWrapper(
                        KotlinEngineWrapper(KotlinScriptEngineFactory(cl, zapJar.toString())))
        LOGGER.info("Kotlin engine loaded.")

    }

    private val extScript: ExtensionScript by lazy {
        Control.getSingleton()
                .extensionLoader
                .getExtension(ExtensionScript.NAME) as ExtensionScript
    }

}