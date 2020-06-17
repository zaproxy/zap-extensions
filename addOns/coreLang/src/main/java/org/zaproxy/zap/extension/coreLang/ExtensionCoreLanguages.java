/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2014 The ZAP Development Team
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
package org.zaproxy.zap.extension.coreLang;

import java.nio.file.Paths;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.extension.ExtensionAdaptor;
import org.zaproxy.zap.extension.lang.LangImporter;

/**
 * An extension which just installs the bundled language file
 *
 * @author psiinon
 */
public class ExtensionCoreLanguages extends ExtensionAdaptor {

    @Override
    public String getName() {
        return "ExtensionCoreLang";
    }

    @Override
    public String getDescription() {
        return Constant.messages.getString("coreLang.desc");
    }

    @Override
    public boolean canUnload() {
        return true;
    }

    @Override
    public void postInstall() {
        // Import the language file
        LangImporter.importLanguagePack(
                Paths.get(Constant.getZapHome(), getAddOn().getFiles().get(0)).toString());
    }
}
