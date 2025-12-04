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

import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;

public abstract class NamedAndTagged<T extends Enum<T>> {

    private String name;
    private Set<T> tags;

    private static <T> List<T> enumValuesInList(Class<T> enumCls) {
        T[] arr = enumCls.getEnumConstants();
        return arr == null ? Collections.emptyList() : Arrays.asList(arr);
    }

    public static <T extends Enum<T>> T getTagForString(String s, Class<T> enumCls) {
        for (T t : enumValuesInList(enumCls)) {
            if (t.name().equals(s)) {
                return t;
            }
        }
        return null;
    }

    public NamedAndTagged(String name) {
        this.name = name;
        this.tags = new HashSet<>();
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public Set<T> getTags() {
        return tags;
    }

    public void setTags(Set<T> tags) {
        this.tags = tags;
    }

    public boolean isTagged(T tag) {
        return tags.contains(tag);
    }

    @Override
    public boolean equals(Object object) {
        if (!(object instanceof NamedAndTagged<?> that)) return false;
        return Objects.equals(name, that.name) && Objects.equals(tags, that.tags);
    }

    @Override
    public int hashCode() {
        return Objects.hash(name, tags);
    }
}
