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
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.TreeMap;
import org.apache.commons.lang3.EnumUtils;
import org.apache.commons.lang3.StringUtils;
import org.parosproxy.paros.CommandLine;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.zaproxy.addon.automation.jobs.JobUtils;
import org.zaproxy.addon.automation.tests.AbstractAutomationTest;
import org.zaproxy.addon.automation.tests.AutomationAlertTest;
import org.zaproxy.addon.automation.tests.AutomationMonitorTest;
import org.zaproxy.addon.automation.tests.AutomationStatisticTest;
import org.zaproxy.addon.automation.tests.UrlPresenceTest;
import org.zaproxy.zap.extension.stats.ExtensionStats;
import org.zaproxy.zap.users.User;

public abstract class AutomationJob implements Comparable<AutomationJob> {

    private static final String EMPTY_SUMMARY = "";
    private static final String NO_EXTRA_CONFIGS = "";
    private static final int ZERO_TESTS = 0;

    public enum Status {
        NOT_STARTED,
        RUNNING,
        COMPLETED
    }

    private String name;
    private Status status = Status.NOT_STARTED;
    private AutomationEnvironment env;
    private final List<AbstractAutomationTest> tests = new ArrayList<>();
    private Map<?, ?> jobData;
    private AutomationPlan plan;

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
    }

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

    public void setJobData(Map<?, ?> jobData) {
        this.jobData = jobData;
    }

    public Map<?, ?> getJobData() {
        return jobData;
    }

    public Status getStatus() {
        return status;
    }

    public void setStatus(Status status) {
        this.status = status;
    }

    public AutomationData getData() {
        return null;
    }

    public AutomationData getParameters() {
        return null;
    }

    public String getSummary() {
        return EMPTY_SUMMARY;
    }

    public int addDefaultTests(AutomationProgress progress) {
        return ZERO_TESTS;
    }

    public void showDialog() {}

    /**
     * Called when the plan is started - can be used by jobs to save state if necessary.
     *
     * @see #planFinished
     */
    public void planStarted() {}

    /**
     * Called when the plan is finished - can be used by jobs to revert state if necessary.
     *
     * @see #planStarted
     */
    public void planFinished() {}

    public abstract void runJob(AutomationEnvironment env, AutomationProgress progress);

    public abstract String getType();

    public abstract Order getOrder();

    public abstract Object getParamMethodObject();

    public abstract String getParamMethodName();

    /**
     * Returns true if this job is just a way to make data available to reports - running it will do
     * nothing.
     */
    public boolean isDataJob() {
        return false;
    }

    /**
     * Applies the custom parameter for the job
     *
     * @param name name of the parameter
     * @param value value of the parameter
     * @return {@code true} if the parameter was applied/consumed, {@code false} otherwise.
     */
    public boolean applyCustomParameter(String name, String value) {
        return false;
    }

    /**
     * Verifies the custom parameter for the job
     *
     * @param name name of the parameter
     * @param value value of the parameter
     * @param progress to store the warnings/errors which occurred during verification
     * @return {@code true} if the parameter was verified, {@code false} otherwise.
     * @since 0.3.0
     * @see #applyCustomParameter(String, String)
     */
    public boolean verifyCustomParameter(String name, String value, AutomationProgress progress) {
        return getCustomConfigParameters().containsKey(name);
    }

    public String getTemplateDataMin() {
        return ExtensionAutomation.getResourceAsString(this.getType() + "-min.yaml");
    }

    public String getTemplateDataMax() {
        return ExtensionAutomation.getResourceAsString(this.getType() + "-max.yaml");
    }

    public void setEnv(AutomationEnvironment env) {
        this.env = env;
    }

    public AutomationEnvironment getEnv() {
        return this.env;
    }

    public AutomationPlan getPlan() {
        return plan;
    }

    public void resetAndSetChanged() {
        reset();
        setChanged();
    }

    public void setChanged() {
        AutomationEventPublisher.publishEvent(AutomationEventPublisher.JOB_CHANGED, this, null);
        this.plan.setChanged();
    }

    public void setPlan(AutomationPlan plan) {
        this.plan = plan;
    }

    public void reset() {
        this.status = Status.NOT_STARTED;
        this.tests.stream().forEach(AbstractAutomationTest::reset);
    }

    public void applyParameters(AutomationProgress progress) {
        verifyOrApplyParameters(
                this.getParamMethodObject(), this.getParamMethodName(), progress, false);
    }

    public void verifyParameters(AutomationProgress progress) {
        verifyOrApplyParameters(
                this.getParamMethodObject(), this.getParamMethodName(), progress, true);
    }

    @SuppressWarnings({"unchecked", "rawtypes"})
    void verifyOrApplyParameters(
            Object obj, String optionsGetterName, AutomationProgress progress, boolean verify) {
        if (this.jobData == null) {
            return;
        }
        Object paramsObj = jobData.get("parameters");
        if (paramsObj == null) {
            return;
        }
        if (!(paramsObj instanceof LinkedHashMap<?, ?>)) {
            if (verify) {
                progress.error(Constant.messages.getString("automation.error.job.data", paramsObj));
            }
            return;
        }
        LinkedHashMap<?, ?> params = (LinkedHashMap<?, ?>) paramsObj;

        Object options = JobUtils.getJobOptions(this, progress);
        if (progress.hasErrors()) {
            return;
        }
        Map<String, Method> methodMap = null;

        if (options != null) {
            try {
                Method[] methods = options.getClass().getMethods();
                methodMap = new HashMap<>(methods.length);
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

            String resolvedValue;
            if (env != null && !verify) {
                resolvedValue = env.replaceVars(param.getValue());
            } else {
                resolvedValue = param.getValue().toString();
            }
            if (!verify) {
                if (applyCustomParameter(key, resolvedValue)) {
                    progress.info(
                            Constant.messages.getString(
                                    "automation.info.setparam",
                                    this.getType(),
                                    key,
                                    param.getValue().toString()));
                    continue;
                }
            } else {
                if (verifyCustomParameter(key, resolvedValue, progress)) {
                    continue;
                }
            }
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
                                            this.getType(),
                                            key,
                                            param.getValue()));
                            continue;
                        } catch (IllegalArgumentException e1) {
                            if (Enum.class.isAssignableFrom(paramType)) {
                                progress.error(
                                        Constant.messages.getString(
                                                "automation.error.options.badenum",
                                                this.getType(),
                                                key,
                                                EnumUtils.getEnumList((Class<Enum>) paramType)));
                            } else {
                                progress.error(
                                        Constant.messages.getString(
                                                "automation.error.options.badbool",
                                                this.getType(),
                                                key,
                                                param.getValue()));
                            }
                            continue;
                        }
                        if (!verify) {
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
                                                optMethod.getParameterTypes()[0]
                                                        .getCanonicalName()));
                            }
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

    private static boolean testTypeExists(ArrayList<?> tests, String type) {
        return tests.stream()
                .map(LinkedHashMap.class::cast)
                .map(t -> t.get("type"))
                .anyMatch(type::equals);
    }

    protected void addTests(Object testsObj, AutomationProgress progress) {
        if (testsObj == null) {
            return;
        }
        if (!(testsObj instanceof ArrayList<?>)) {
            progress.error(Constant.messages.getString("automation.error.job.data", testsObj));
            return;
        }

        ExtensionStats extStats =
                Control.getSingleton().getExtensionLoader().getExtension(ExtensionStats.class);

        if (extStats == null || extStats.getInMemoryStats() == null) {
            if (testTypeExists((ArrayList<?>) testsObj, "stats")) {
                progress.warn(
                        Constant.messages.getString(
                                "automation.tests.stats.nullInMemoryStats", getType()));
            }
            if (testTypeExists((ArrayList<?>) testsObj, "monitor")) {
                progress.warn(
                        Constant.messages.getString(
                                "automation.tests.monitor.nullInMemoryStats", getType()));
            }
        }

        for (Object testObj : (ArrayList<?>) testsObj) {
            if (!(testObj instanceof LinkedHashMap<?, ?>)) {
                progress.error(Constant.messages.getString("automation.error.job.data", testObj));
                continue;
            }
            LinkedHashMap<?, ?> testData = (LinkedHashMap<?, ?>) testObj;
            Object testType = testData.get("type");
            AbstractAutomationTest test;
            if ("stats".equals(testType)) {
                try {
                    test = new AutomationStatisticTest(testData, this, progress);
                } catch (IllegalArgumentException e) {
                    progress.warn(e.getMessage());
                    continue;
                }
                addTest(test);
                progress.info(
                        Constant.messages.getString(
                                "automation.tests.add", getType(), testType, test.getName()));
            } else if ("alert".equals(testType)) {
                try {
                    test = new AutomationAlertTest(testData, this, progress);
                } catch (IllegalArgumentException e) {
                    progress.warn(e.getMessage());
                    continue;
                }
                addTest(test);
                progress.info(
                        Constant.messages.getString(
                                "automation.tests.add", getType(), testType, test.getName()));
            } else if ("url".equals(testType)) {
                try {
                    test = new UrlPresenceTest(testData, this, progress);
                } catch (IllegalArgumentException e) {
                    progress.warn(e.getMessage());
                    continue;
                }
                addTest(test);
                progress.info(
                        Constant.messages.getString(
                                "automation.tests.add", getType(), testType, test.getName()));
            } else if ("monitor".equals(testType)) {
                if (!this.supportsMonitorTests()) {
                    progress.warn(
                            Constant.messages.getString(
                                    "automation.tests.monitorNotSupported",
                                    getName(),
                                    this.getType()));
                } else {
                    try {
                        test = new AutomationMonitorTest(testData, this, progress);
                    } catch (IllegalArgumentException e) {
                        progress.warn(e.getMessage());
                        continue;
                    }
                    addTest(test);
                    progress.info(
                            Constant.messages.getString(
                                    "automation.tests.add", getType(), testType, test.getName()));
                }
            } else {
                progress.warn(
                        Constant.messages.getString("automation.tests.invalidType", testType));
            }
        }
    }

    public void addTest(AbstractAutomationTest test) {
        tests.add(test);
    }

    public boolean removeTest(AbstractAutomationTest test) {
        return tests.remove(test);
    }

    public void logTestsToProgress(AutomationProgress progress) {
        tests.forEach(t -> t.logToProgress(progress));
    }

    public boolean supportsMonitorTests() {
        return false;
    }

    public boolean runMonitorTests(AutomationProgress progress) {
        if (!supportsMonitorTests()) {
            return false;
        }

        return tests.stream()
                .filter(t -> t.getClass().equals(AutomationMonitorTest.class))
                .allMatch(t -> t.runTest(progress));
    }

    public static <T> T safeCast(Object property, Class<T> clazz) {
        if (clazz.isInstance(property)) {
            return clazz.cast(property);
        }
        return null;
    }

    public List<AbstractAutomationTest> getTests() {
        return tests;
    }

    @SuppressWarnings({"unchecked", "rawtypes"})
    private <T> T stringToType(String str, T t) {
        if (String.class.equals(t)) {
            return (T) str;
        } else if (Integer.class.equals(t) || int.class.equals(t)) {
            return (T) (Object) Integer.parseInt(str);
        } else if (Long.class.equals(t) || long.class.equals(t)) {
            return (T) (Object) Long.parseLong(str);
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

    private String valueToYaml(Object val) {
        if (val == null) {
            return "";
        } else if (val instanceof String) {
            return (String) val;
        } else if (val instanceof Integer) {
            return val.toString();
        } else if (val instanceof Long) {
            return val.toString();
        } else if (int.class.isInstance(val)) {
            return val.toString();
        } else if (val instanceof Boolean) {
            return val.toString();
        } else if (boolean.class.isInstance(val)) {
            return val.toString();
        } else if (Enum.class.isAssignableFrom(val.getClass())) {
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
                    || Long.class.equals(c)
                    || long.class.equals(c)
                    || Boolean.class.equals(c)
                    || boolean.class.equals(c)
                    || Enum.class.isAssignableFrom(c)) {
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
        return new HashMap<>();
    }

    public List<JobResultData> getJobResultData() {
        return new ArrayList<>();
    }

    public String getExtraConfigFileData() {
        return NO_EXTRA_CONFIGS;
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
        Map<String, String> sortedParams = new TreeMap<>(params);

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
        Map<String, String> kvMap = new HashMap<>();
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

    public AutomationJob newJob() throws AutomationJobException {
        try {
            return this.getClass().getConstructor().newInstance();
        } catch (Exception e) {
            throw new AutomationJobException("Failed to create new job", e);
        }
    }

    public void verifyUser(String username, AutomationProgress progress) {
        if (!StringUtils.isEmpty(username) && !this.getEnv().getAllUserNames().contains(username)) {
            progress.error(
                    Constant.messages.getString(
                            "automation.error.job.baduser", this.getName(), username));
        }
    }

    public User getUser(String username, AutomationProgress progress) {
        User user = null;
        if (!StringUtils.isEmpty(username)) {
            user = this.getEnv().getUser(username);
            if (user == null) {
                progress.error(
                        Constant.messages.getString(
                                "automation.error.job.baduser", this.getName(), username));
            }
        }
        return user;
    }

    protected void sleep(long millis) {
        try {
            Thread.sleep(millis);
        } catch (InterruptedException e) {
            // Ignore
        }
    }
}
