/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2015 The ZAP Development Team
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
package org.zaproxy.zap.extension.fuzz;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class FuzzerPayloadCategory implements Comparable<FuzzerPayloadCategory> {

    private final String name;
    private final String fullName;
    private final List<FuzzerPayloadCategory> categories;
    private final List<FuzzerPayloadSource> payloadSources;

    public FuzzerPayloadCategory(
            String name,
            String fullName,
            List<FuzzerPayloadCategory> categories,
            List<FuzzerPayloadSource> files) {
        this.name = name;
        this.fullName = fullName;

        List<FuzzerPayloadCategory> sortedCategories = new ArrayList<>(categories);
        Collections.sort(sortedCategories);
        this.categories = Collections.unmodifiableList(sortedCategories);

        List<FuzzerPayloadSource> sortedSources = new ArrayList<>(files);
        Collections.sort(sortedSources);
        this.payloadSources = Collections.unmodifiableList(sortedSources);
    }

    public String getName() {
        return name;
    }

    public String getFullName() {
        return fullName;
    }

    public List<FuzzerPayloadCategory> getSubCategories() {
        return categories;
    }

    public List<FuzzerPayloadSource> getFuzzerPayloadSources() {
        return payloadSources;
    }

    @Override
    public String toString() {
        return getName();
    }

    @Override
    public int compareTo(FuzzerPayloadCategory other) {
        if (other == null) {
            return 1;
        }
        int result = getName().compareTo(other.getName());
        if (result != 0) {
            return result;
        }
        return getFullName().compareTo(other.getFullName());
    }
}
