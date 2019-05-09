/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2018 The ZAP Development Team
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
package org.zaproxy.zap.extension.groovy;

/**
 * This class wraps the AddOnLoader for the GroovyScript execution
 *
 * <p>It is necessary, because the AddOnLoader has no overload for loadClass(String name, boolean
 * resolve), but the GroovyClassLoader calls parent.loadClass(String name, boolean resolve). If this
 * happens no AddOn class would be resolved. So we delegate the loadClass call to the
 * loadClass(String name)
 */
public class AddOnClassLoaderWrapper extends ClassLoader {
    protected AddOnClassLoaderWrapper(ClassLoader parent) {
        super(parent);
    }

    @Override
    public Class<?> loadClass(String name) throws ClassNotFoundException {
        return getParent().loadClass(name);
    }

    @Override
    protected Class<?> loadClass(String name, boolean resolve) throws ClassNotFoundException {
        return getParent().loadClass(name);
    }
}
