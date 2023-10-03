/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2023 The ZAP Development Team
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
package org.zaproxy.zap.extension.scripts;

import org.parosproxy.paros.Constant;
import org.zaproxy.zap.common.VersionedAbstractParam;

public class ScriptConsoleOptions extends VersionedAbstractParam {

    private static String BASE_KEY = "script.console";
    private static String DEFAULT_SCRIPT_CHANGED_BEHAVIOUR =
            BASE_KEY + ".defaultScriptChangedBehaviour";

    /**
     * The version of the configurations. Used to keep track of configurations changes between
     * releases, if updates are needed.
     */
    private static final int CURRENT_CONFIG_VERSION = 1;

    private DefaultScriptChangedBehaviour defaultScriptChangedBehaviour;

    public DefaultScriptChangedBehaviour getDefaultScriptChangedBehaviour() {
        return defaultScriptChangedBehaviour;
    }

    public void setDefaultScriptChangedBehaviour(DefaultScriptChangedBehaviour behaviour) {
        this.defaultScriptChangedBehaviour = behaviour;
        getConfig().setProperty(DEFAULT_SCRIPT_CHANGED_BEHAVIOUR, behaviour.name());
    }

    @Override
    protected void parseImpl() {
        defaultScriptChangedBehaviour =
                getEnum(
                        DEFAULT_SCRIPT_CHANGED_BEHAVIOUR,
                        DefaultScriptChangedBehaviour.ASK_EACH_TIME);
    }

    @Override
    protected String getConfigVersionKey() {
        return BASE_KEY + VERSION_ATTRIBUTE;
    }

    @Override
    protected int getCurrentVersion() {
        return CURRENT_CONFIG_VERSION;
    }

    @Override
    protected void updateConfigsImpl(int fileVersion) {}

    public enum DefaultScriptChangedBehaviour {
        KEEP,
        REPLACE,
        ASK_EACH_TIME;

        @Override
        public String toString() {
            switch (this) {
                case KEEP:
                    return Constant.messages.getString("scripts.changed.keep");
                case REPLACE:
                    return Constant.messages.getString("scripts.changed.replace");
                case ASK_EACH_TIME:
                default:
                    return Constant.messages.getString("scripts.changed.askEachTime");
            }
        }
    }
}
