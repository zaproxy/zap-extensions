/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2021 The ZAP Development Team
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
package org.zaproxy.addon.reports;

import org.parosproxy.paros.Constant;
import org.thymeleaf.context.ITemplateContext;
import org.thymeleaf.messageresolver.AbstractMessageResolver;

public class ReportMessageResolver extends AbstractMessageResolver {

    private Template template;

    public ReportMessageResolver(Template template) {
        this.template = template;
    }

    @Override
    public String resolveMessage(
            ITemplateContext context, Class<?> origin, String key, Object[] messageParameters) {
        String str = template.getI18nString(key, messageParameters);
        if (str != null) {
            return str;
        }
        return Constant.messages.getString(ExtensionReports.PREFIX + "." + key, messageParameters);
    }

    @Override
    public String createAbsentMessageRepresentation(
            ITemplateContext context, Class<?> origin, String key, Object[] messageParameters) {
        String str = template.getI18nString(key, messageParameters);
        if (str != null) {
            return str;
        }
        return Constant.messages.getString(ExtensionReports.PREFIX + "." + key, messageParameters);
    }
}
