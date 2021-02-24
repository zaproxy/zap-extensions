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
package org.zaproxy.addon.automation;

import java.lang.reflect.Method;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Map.Entry;
import java.util.TreeMap;
import org.parosproxy.paros.CommandLine;
import org.parosproxy.paros.Constant;

public abstract class AutomationJob implements Comparable<AutomationJob> {

    private String name;

    public enum Order {
        RUN_FIRST,
        CONFIGS,
        FIRST_EXPLORE,
        EXPLORE,
        LAST_EXPLORE,
        AFTER_EXPLORE,
        FIRST_ATTACK,
        ATTACK,
        LAST_ATTACK,
        AFTER_ATTACK,
        REPORT,
        RUN_LAST
    };

    @Override
    public int compareTo(AutomationJob o) {
        int order = this.getOrder().ordinal() - o.getOrder().ordinal();
        if (order == 0) {
            return this.getName().compareTo(o.getName());
        }
        return order;
    }

    public String getName() {
        return name != null ? name : getType();
    }

    public void setName(String name) {
        this.name = name;
    }

    public abstract void runJob(
            AutomationEnvironment env, LinkedHashMap<?, ?> jobData, AutomationProgress progress);

    public abstract String getType();

    public abstract Order getOrder();

    public abstract Object getParamMethodObject();

    public abstract String getParamMethodName();

    public boolean applyCustomParameter(String name, String value) {
        return false;
    }

    public String getTemplateDataMin() {
        return ExtensionAutomation.getResourceAsString(this.getType() + "-min.yaml");
    }

    public String getTemplateDataMax() {
        return ExtensionAutomation.getResourceAsString(this.getType() + "-max.yaml");
    }

    public void applyParameters(LinkedHashMap<?, ?> params, AutomationProgress progress) {
        applyParameters(this.getParamMethodObject(), this.getParamMethodName(), params, progress);
    }

    protected void applyParameters(
            Object obj,
            String optionsGetterName,
            LinkedHashMap<?, ?> params,
            AutomationProgress progress) {
        if (params == null) {
            return;
        }
        Object options = null;
        Map<String, Method> methodMap = null;
        if (obj != null && optionsGetterName != null) {
            try {
                Method method = obj.getClass().getDeclaredMethod(optionsGetterName);
                method.setAccessible(true);
                options = method.invoke(obj);
                Method[] methods = options.getClass().getMethods();
                methodMap = new HashMap<String, Method>(methods.length);
                for (Method m : methods) {
                    methodMap.put(m.getName(), m);
                }
            } catch (Exception e1) {
                progress.error(
                        Constant.messages.getString(
                                "automation.error.options.methods",
                                obj.getClass().getCanonicalName(),
                                optionsGetterName,
                                e1.getMessage()));
                return;
            }
        }

        for (Entry<?, ?> param : params.entrySet()) {
            String key = param.getKey().toString();
            if (param.getValue() == null) {
                continue;
            }
            if (applyCustomParameter(key, param.getValue().toString())) {
                progress.info(
                        Constant.messages.getString(
                                "automation.info.setparam",
                                this.getType(),
                                key,
                                param.getValue().toString()));
                continue;
            }
            if (methodMap != null) {
                String paramMethodName = "set" + key.toUpperCase().charAt(0) + key.substring(1);
                Method optMethod = methodMap.get(paramMethodName);
                if (optMethod != null) {
                    if (optMethod.getParameterCount() > 0) {
                        Object value = null;
                        try {
                            value =
                                    stringToType(
                                            param.getValue().toString(),
                                            optMethod.getParameterTypes()[0]);
                        } catch (NumberFormatException e1) {
                            progress.error(
                                    Constant.messages.getString(
                                            "automation.error.options.badint",
                                            this.getType(),
                                            key,
                                            param.getValue()));
                            continue;
                        } catch (IllegalArgumentException e1) {
                            progress.error(
                                    Constant.messages.getString(
                                            "automation.error.options.badbool",
                                            this.getType(),
                                            key,
                                            param.getValue()));
                            continue;
                        }
                        if (value != null) {
                            try {
                                optMethod.invoke(options, value);
                                progress.info(
                                        Constant.messages.getString(
                                                "automation.info.setparam",
                                                this.getType(),
                                                key,
                                                value));
                            } catch (Exception e) {
                                progress.error(
                                        Constant.messages.getString(
                                                "automation.error.options.badcall",
                                                obj.getClass().getCanonicalName(),
                                                paramMethodName,
                                                e.getMessage()));
                            }
                        } else {
                            progress.error(
                                    Constant.messages.getString(
                                            "automation.error.options.badtype",
                                            obj.getClass().getCanonicalName(),
                                            paramMethodName,
                                            optMethod.getParameterTypes()[0].getCanonicalName()));
                        }
                    }
                } else {
                    // This is likely to be caused by the user using an invalid name, rather than a
                    // coding issue
                    progress.warn(
                            Constant.messages.getString(
                                    "automation.error.options.unknown", this.getType(), key));
                }
            } else {
                // Not a custom param and no options object
                progress.warn(
                        Constant.messages.getString(
                                "automation.error.options.unknown", this.getType(), key));
            }
        }
    }

    @SuppressWarnings("unchecked")
    private <T> T stringToType(String str, T t) {
        if (String.class.equals(t)) {
            return (T) str;
        } else if (Integer.class.equals(t) || int.class.equals(t)) {
            return (T) (Object) Integer.parseInt(str);
        } else if (Boolean.class.equals(t) || boolean.class.equals(t)) {
            // Don't use Boolean.parseBoolean as it won't reject illegal values
            String s = str.trim().toLowerCase();
            if ("true".equals(s)) {
                return (T) Boolean.TRUE;
            } else if ("false".equals(s)) {
                return (T) Boolean.FALSE;
            }
            throw new IllegalArgumentException("Invalid boolean value: " + str);
        }

        return null;
    }

    private <T> String valueToYaml(Object val) {
        if (val == null) {
            return "";
        } else if (String.class.isInstance(val)) {
            return (String) val;
        } else if (Integer.class.isInstance(val)) {
            return val.toString();
        } else if (int.class.isInstance(val)) {
            return val.toString();
        } else if (Boolean.class.isInstance(val)) {
            return val.toString();
        } else if (boolean.class.isInstance(val)) {
            return val.toString();
        }
        return null;
    }

    private boolean isSupportedGetter(Method m) {
        if (getVarNameFromGetter(m.getName()) != null && m.getParameterCount() == 0) {
            Class<?> c = m.getReturnType();
            if (String.class.equals(c)
                    || Integer.class.equals(c)
                    || int.class.equals(c)
                    || Boolean.class.equals(c)
                    || boolean.class.equals(c)) {
                return true;
            }
        }
        return false;
    }

    private String getVarNameFromGetter(String name) {
        int i;
        if (name.startsWith("get")) {
            i = 3;
        } else if (name.startsWith("is")) {
            i = 2;
        } else {
            return null;
        }
        return name.toLowerCase().charAt(i) + name.substring(i + 1);
    }

    public Map<String, String> getCustomConfigParameters() {
        return new HashMap<String, String>();
    }

    public String getExtraConfigFileData() {
        return "";
    }

    public String getConfigFileData() {
        StringBuilder sb = new StringBuilder();
        sb.append("  - type: ");
        sb.append(this.getType());
        sb.append("\n");
        sb.append("    name: ");
        sb.append(this.getName());
        sb.append("\n");
        sb.append("    parameters:\n");

        Map<String, String> params = getCustomConfigParameters();
        Object paramMethodObj = this.getParamMethodObject();
        if (paramMethodObj != null) {
            Map<String, String> configParams =
                    this.getConfigParameters(paramMethodObj, this.getParamMethodName());
            if (configParams != null) {
                params.putAll(configParams);
            }
        }
        Map<String, String> sortedParams = new TreeMap<String, String>(params);

        for (Entry<String, String> entry : sortedParams.entrySet()) {
            sb.append("      ");
            sb.append(entry.getKey());
            sb.append(": ");
            sb.append(entry.getValue());
            sb.append("\n");
        }
        sb.append(getExtraConfigFileData());

        return sb.toString();
    }

    /**
     * Always returns false. Override to exclude option parameters from the configs generated.
     *
     * @param param the parameter to check for exclusion
     * @return True if the parameter is excluded, false otherwise
     */
    public boolean isExcludeParam(String param) {
        return false;
    }

    public Map<String, String> getConfigParameters(Object obj, String optionsGetterName) {
        Map<String, String> kvMap = new HashMap<String, String>();
        try {
            Method method = obj.getClass().getDeclaredMethod(optionsGetterName);
            method.setAccessible(true);
            Object options = method.invoke(obj);
            Method[] methods = options.getClass().getMethods();
            for (Method m : methods) {
                if (isSupportedGetter(m)) {
                    try {
                        String key = getVarNameFromGetter(m.getName());
                        if (isExcludeParam(key)) {
                            continue;
                        }
                        if (setterExistsForKey(key, methods)) {
                            Object value = m.invoke(options);
                            if (value == null) {
                                kvMap.put(key, "");
                            } else {
                                String valStr = valueToYaml(value);
                                if (valStr != null) {
                                    kvMap.put(key, valStr);
                                }
                            }
                        }
                    } catch (Exception e) {
                        CommandLine.error(
                                "Failed to call getter on " + options.getClass().getCanonicalName(),
                                e);
                    }
                }
            }
        } catch (Exception e) {
            CommandLine.error(
                    "Failed to access methods on " + obj.getClass().getCanonicalName(), e);
        }
        return kvMap;
    }

    private boolean setterExistsForKey(String key, Method[] methods) {
        String methodName = "set" + key.toUpperCase().charAt(0) + key.substring(1);
        for (Method m : methods) {
            if (methodName.equals(m.getName())) {
                return true;
            }
        }
        return false;
    }
}
