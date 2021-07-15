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
package org.zaproxy.addon.automation.jobs;

import java.lang.reflect.Method;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import org.apache.commons.lang3.EnumUtils;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.Plugin.AlertThreshold;
import org.parosproxy.paros.core.scanner.Plugin.AttackStrength;
import org.zaproxy.addon.automation.AutomationJob;
import org.zaproxy.addon.automation.AutomationProgress;

public class JobUtils {

    public static AttackStrength parseAttackStrength(
            Object o, String jobName, AutomationProgress progress) {
        AttackStrength strength = null;
        if (o == null) {
            return null;
        }
        if (o instanceof String) {
            try {
                strength = AttackStrength.valueOf(((String) o).toUpperCase());
            } catch (Exception e) {
                progress.warn(
                        Constant.messages.getString("automation.error.ascan.strength", jobName, o));
            }
        } else {
            progress.warn(
                    Constant.messages.getString("automation.error.ascan.strength", jobName, o));
        }
        return strength;
    }

    public static AlertThreshold parseAlertThreshold(
            Object o, String jobName, AutomationProgress progress) {
        AlertThreshold threshold = null;
        if (o == null) {
            return null;
        }
        if (o instanceof String) {
            try {
                threshold = AlertThreshold.valueOf(((String) o).toUpperCase());
            } catch (Exception e) {
                progress.warn(
                        Constant.messages.getString(
                                "automation.error.ascan.threshold", jobName, o));
            }
        } else if (o instanceof Boolean && (!(Boolean) o)) {
            // This will happen if OFF is not quoted
            threshold = AlertThreshold.OFF;
        } else {
            progress.warn(
                    Constant.messages.getString("automation.error.ascan.threshold", jobName, o));
        }
        return threshold;
    }

    public static Object getJobOptions(AutomationJob job, AutomationProgress progress) {
        Object obj = job.getParamMethodObject();
        String optionsGetterName = job.getParamMethodName();
        if (obj != null && optionsGetterName != null) {
            try {
                Method method = obj.getClass().getDeclaredMethod(optionsGetterName);
                method.setAccessible(true);
                return method.invoke(obj);
            } catch (Exception e1) {
                progress.error(
                        Constant.messages.getString(
                                "automation.error.options.methods",
                                obj.getClass().getCanonicalName(),
                                optionsGetterName,
                                e1.getMessage()));
                return null;
            }
        }
        return null;
    }

    @SuppressWarnings({"unchecked", "rawtypes"})
    public static void applyParamsToObject(
            LinkedHashMap<?, ?> params,
            Object object,
            String objectName,
            String[] ignore,
            AutomationProgress progress) {
        if (params == null || object == null) {
            return;
        }
        Map<String, Method> methodMap = null;
        List<String> ignoreList = Collections.emptyList();
        if (ignore != null) {
            ignoreList = Arrays.asList(ignore);
        }

        try {
            Method[] methods = object.getClass().getMethods();
            methodMap = new HashMap<>(methods.length);
            for (Method m : methods) {
                System.out.println("SBSB map " + m.getName()); // TODO
                methodMap.put(m.getName(), m);
            }
        } catch (Exception e1) {
            // TODO log error too?
            progress.error(
                    Constant.messages.getString(
                            "automation.error.options.methods",
                            objectName, // TODO changed params
                            e1.getMessage()));
            return;
        }

        for (Entry<?, ?> param : params.entrySet()) {
            String key = param.getKey().toString();
            System.out.println("SBSB key = " + key + " val = " + param.getValue()); // TODO
            if (param.getValue() == null) {
                continue;
            }

            String resolvedValue = param.getValue().toString();
            if (methodMap != null) {
                String paramMethodName = "set" + key.toUpperCase().charAt(0) + key.substring(1);
                Method optMethod = methodMap.get(paramMethodName);
                if (optMethod != null) {
                    if (optMethod.getParameterCount() > 0) {
                        Object value = null;
                        Class<?> paramType = optMethod.getParameterTypes()[0];
                        try {
                            value = stringToType(resolvedValue, paramType);
                        } catch (NumberFormatException e1) {
                            progress.error(
                                    Constant.messages.getString(
                                            "automation.error.options.badint",
                                            objectName,
                                            key,
                                            param.getValue()));
                            continue;
                        } catch (IllegalArgumentException e1) {
                            if (Enum.class.isAssignableFrom(paramType)) {
                                progress.error(
                                        Constant.messages.getString(
                                                "automation.error.options.badenum",
                                                objectName,
                                                key,
                                                EnumUtils.getEnumList((Class<Enum>) paramType)));
                            } else {
                                progress.error(
                                        Constant.messages.getString(
                                                "automation.error.options.badbool",
                                                objectName,
                                                key,
                                                param.getValue()));
                            }
                            continue;
                        }
                        if (value != null) {
                            try {
                                optMethod.invoke(object, value);
                                progress.info(
                                        Constant.messages.getString(
                                                "automation.info.setparam",
                                                objectName, // TODO changed param
                                                key,
                                                value));
                            } catch (Exception e) {
                                progress.error(
                                        Constant.messages.getString(
                                                "automation.error.options.badcall",
                                                objectName,
                                                paramMethodName,
                                                e.getMessage()));
                            }
                        } else {
                            progress.error(
                                    Constant.messages.getString(
                                            "automation.error.options.badtype",
                                            objectName, // TODO changed param
                                            paramMethodName,
                                            optMethod.getParameterTypes()[0].getCanonicalName()));
                        }
                    }
                } else if (ignoreList.contains(key)) {
                    // Ignore :)
                } else {
                    // This is likely to be caused by the user using an invalid name, rather than a
                    // coding issue
                    progress.warn(
                            Constant.messages.getString(
                                    "automation.error.options.unknown", objectName, key));
                }
            } else {
                // Not a custom param and no options object TODO dont need this?
                progress.warn(
                        Constant.messages.getString(
                                "automation.error.options.unknown", objectName, key));
            }
        }
    }

    public static void applyObjectToObject(
            Object srcObject,
            Object destObject,
            String objectName,
            String[] ignore,
            AutomationProgress progress) {
        List<String> ignoreList = Collections.emptyList();
        if (ignore != null) {
            ignoreList = Arrays.asList(ignore);
        }

        try {
            Method[] methods = srcObject.getClass().getMethods();
            for (Method m : methods) {
                String getterName = m.getName();
                if (getterName.startsWith("get")
                        && m.getParameterCount() == 0
                        && !getterName.equals("getClass")
                        && !ignoreList.contains(getterName)) {
                    // Its a getter so process it
                    String setterName = "s" + getterName.substring(1);
                    try {
                        Object value = m.invoke(srcObject);
                        if (value == null) {
                            continue;
                        }

                        Method setterMethod = null;
                        try {
                            setterMethod =
                                    destObject.getClass().getMethod(setterName, m.getReturnType());
                        } catch (Exception e) {
                            // Ignore
                        }
                        if (setterMethod == null) {
                            Class<?> c = toBaseClass(m.getReturnType());
                            System.out.println(
                                    "SBSB origClass "
                                            + m.getReturnType()
                                            + " baseClass "
                                            + c); // TODO
                            if (c != null) {
                                try {
                                    setterMethod = destObject.getClass().getMethod(setterName, c);
                                } catch (Exception e) {
                                    // Ignore
                                }
                            }
                        }
                        if (setterMethod != null) {
                            setterMethod.invoke(destObject, value);
                        } else {
                            System.out.println(
                                    "SBSB failed to find method "
                                            + setterName
                                            + " on "
                                            + destObject.getClass().getCanonicalName()); // TODO
                        }

                    } catch (Exception e) {
                        // TODO Auto-generated catch block
                        e.printStackTrace();
                    }
                }
            }

        } catch (Exception e1) {
            // TODO log error too?
            progress.error(
                    Constant.messages.getString(
                            "automation.error.options.methods",
                            objectName, // TODO changed params
                            e1.getMessage()));
            return;
        }
    }

    private static Class<?> toBaseClass(Class<?> origClass) {
        if (origClass.equals(Integer.class)) {
            return int.class;
        }
        if (origClass.equals(Long.class)) {
            return long.class;
        }
        if (origClass.equals(Boolean.class)) {
            return boolean.class;
        }
        return null;
    }

    @SuppressWarnings({"unchecked", "rawtypes"})
    private static <T> T stringToType(String str, T t) {
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
        } else if (Enum.class.isAssignableFrom((Class<T>) t)) {
            T enumType = (T) EnumUtils.getEnumIgnoreCase((Class<Enum>) t, str);
            if (enumType != null) {
                return enumType;
            }
            throw new IllegalArgumentException(
                    "Enum value must be one of " + EnumUtils.getEnumList((Class<Enum>) t));
        }

        return null;
    }

    public static int unBox(Integer i) {
        if (i == null) {
            return 0;
        }
        return i;
    }

    public static long unBox(Long i) {
        if (i == null) {
            return 0;
        }
        return i;
    }

    public static boolean unBox(Boolean i) {
        if (i == null) {
            return false;
        }
        return i;
    }
}
