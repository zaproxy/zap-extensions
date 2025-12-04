/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2025 The ZAP Development Team
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
package org.zaproxy.zap.extension.foxhound.taint;

import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;
import org.zaproxy.zap.extension.foxhound.config.FoxhoundConstants;

public class SourceSinkUtils {

    public static Set<SourceTag> getSourceTags(SourceSinkProvider ss) {
        Set<SourceTag> tags = new HashSet<>();
        for (SourceTag t : SourceTag.values()) {
            Set<String> tagNames = FoxhoundConstants.getSourceNamesWithTag(t);
            if (!Collections.disjoint(ss.getSources(), tagNames)) {
                tags.add(t);
            }
        }
        return tags;
    }

    public static String getOperationNameList(Collection<TaintOperation> ops) {
        return String.join(", ", ops.stream().map(TaintOperation::getOperation).toList());
    }

    public static String getSourceSinkLabel(SourceSinkProvider ss) {
        return getOperationNameList(ss.getSources()) + " \u2192 " + ss.getSink().getOperation();
    }
}
