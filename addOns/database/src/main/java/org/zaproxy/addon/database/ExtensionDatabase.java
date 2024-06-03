/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2024 The ZAP Development Team
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
package org.zaproxy.addon.database;

import java.util.List;
import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.core.LoggerContext;
import org.apache.logging.log4j.core.config.Configuration;
import org.apache.logging.log4j.core.config.LoggerConfig;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.extension.ExtensionAdaptor;

public class ExtensionDatabase extends ExtensionAdaptor {

    public ExtensionDatabase() {
        super(ExtensionDatabase.class.getSimpleName());

        setI18nPrefix("database");
    }

    @Override
    public String getUIName() {
        return Constant.messages.getString("database.ext.name");
    }

    @Override
    public String getDescription() {
        return Constant.messages.getString("database.ext.desc");
    }

    @Override
    public boolean canUnload() {
        return true;
    }

    @Override
    public void init() {
        super.init();

        // Suppress warn that HSQLDB is not official supported yet.
        setLogLevel(List.of("org.flywaydb.core.internal.database.base.Database"), Level.ERROR);
    }

    private static void setLogLevel(List<String> classnames, Level level) {
        boolean updateLoggers = false;
        LoggerContext ctx = (LoggerContext) LogManager.getContext(false);
        Configuration configuration = ctx.getConfiguration();
        for (String classname : classnames) {
            LoggerConfig loggerConfig = configuration.getLoggerConfig(classname);
            if (!classname.equals(loggerConfig.getName())) {
                configuration.addLogger(
                        classname,
                        LoggerConfig.newBuilder()
                                .withLoggerName(classname)
                                .withLevel(level)
                                .withConfig(configuration)
                                .build());
                updateLoggers = true;
            }
        }

        if (updateLoggers) {
            ctx.updateLoggers();
        }
    }
}
