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
package org.zaproxy.addon.commonlib.internal;

import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.time.Instant;
import java.util.List;
import org.apache.commons.lang3.StringUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.zaproxy.zap.authentication.AuthenticationCredentials;
import org.zaproxy.zap.authentication.AuthenticationMethod;
import org.zaproxy.zap.authentication.GenericAuthenticationCredentials;
import org.zaproxy.zap.authentication.UsernamePasswordAuthenticationCredentials;

public final class TotpSupport {

    private static final Logger LOGGER = LogManager.getLogger(TotpSupport.class);

    private static Class<?> tacClass;
    private static Method isTotpEnabledMethod;
    private static Method getTotpDataMethod;

    private static Class<?> totpGeneratorClass;
    private static Method setTotpDataMethod;

    private static Method getTotpCodeMethod;
    private static Method setTotpGeneratorMethod;
    private static Method secretMethod;
    private static Method periodMethod;
    private static Method digitsMethod;
    private static Method algorithmMethod;

    private static Constructor<?> totpDataConstructor;
    private static Constructor<UsernamePasswordAuthenticationCredentials> upCredentialsConstructor;
    private static Constructor<GenericAuthenticationCredentials> genericCredentialsConstructor;

    static {
        try {
            tacClass =
                    Class.forName("org.zaproxy.zap.authentication.TotpAuthenticationCredentials");
            isTotpEnabledMethod = tacClass.getMethod("isTotpEnabled");
            getTotpDataMethod = tacClass.getMethod("getTotpData");

            totpGeneratorClass =
                    Class.forName(
                            "org.zaproxy.zap.authentication.TotpAuthenticationCredentials$TotpGenerator");
            Class<?> totpDataClass =
                    Class.forName(
                            "org.zaproxy.zap.authentication.TotpAuthenticationCredentials$TotpData");
            totpDataConstructor =
                    totpDataClass.getDeclaredConstructor(
                            String.class, int.class, int.class, String.class);

            setTotpDataMethod = tacClass.getMethod("setTotpData", totpDataClass);

            secretMethod = totpDataClass.getMethod("secret");
            periodMethod = totpDataClass.getMethod("period");
            digitsMethod = totpDataClass.getMethod("digits");
            algorithmMethod = totpDataClass.getMethod("algorithm");

            Class<?> acClass =
                    Class.forName("org.zaproxy.zap.authentication.AuthenticationCredentials");

            getTotpCodeMethod = acClass.getMethod("getTotpCode", Instant.class);
            setTotpGeneratorMethod = tacClass.getMethod("setTotpGenerator", totpGeneratorClass);

            upCredentialsConstructor =
                    UsernamePasswordAuthenticationCredentials.class.getConstructor(
                            String.class, String.class, boolean.class);
            genericCredentialsConstructor =
                    GenericAuthenticationCredentials.class.getConstructor(
                            String[].class, boolean.class);
        } catch (Exception e) {
            LOGGER.debug("An error occurred while getting the method:", e);
        }
    }

    public static boolean isTotpInCore() {
        return tacClass != null;
    }

    public static String getCode(AuthenticationCredentials credentials) {
        if (getTotpCodeMethod == null) {
            return null;
        }

        try {
            if (hasTotpSecret(credentials)) {
                return (String) getTotpCodeMethod.invoke(credentials, Instant.now());
            }
        } catch (Exception e) {
            LOGGER.warn("An error occurred while getting the TOTP code:", e);
        }

        return null;
    }

    private static boolean hasTotpSecret(AuthenticationCredentials credentials) {
        if (!isTotpCredentials(credentials)) {
            return false;
        }

        try {
            Object coreData = getTotpCoreData(credentials);
            return StringUtils.isNotEmpty((String) secretMethod.invoke(coreData));
        } catch (Exception e) {
            LOGGER.warn("An error occurred while checking the secret:", e);
        }
        return false;
    }

    private static Object getTotpCoreData(AuthenticationCredentials credentials) throws Exception {
        return getTotpDataMethod.invoke(credentials);
    }

    public static void setTotpData(TotpData data, AuthenticationCredentials credentials) {
        if (setTotpDataMethod == null) {
            return;
        }

        try {
            if (!tacClass.isAssignableFrom(credentials.getClass())) {
                return;
            }

            Object coreTotpData =
                    totpDataConstructor.newInstance(
                            data.secret(), data.period(), data.digits(), data.algorithm());

            setTotpDataMethod.invoke(credentials, coreTotpData);
        } catch (Exception e) {
            LOGGER.warn("An error occurred while creating TOTP enabled credentials:", e);
        }
    }

    public static UsernamePasswordAuthenticationCredentials
            createUsernamePasswordAuthenticationCredentials() {
        return createUsernamePasswordAuthenticationCredentials(null, null, null);
    }

    public static UsernamePasswordAuthenticationCredentials
            createUsernamePasswordAuthenticationCredentials(
                    AuthenticationMethod authMethod, String username, String password) {
        if (upCredentialsConstructor != null && hasTotpEnabled(authMethod)) {
            try {
                return upCredentialsConstructor.newInstance(username, password, true);
            } catch (Exception e) {
                LOGGER.warn("An error occurred while creating TOTP enabled credentials:", e);
            }
        }
        return new UsernamePasswordAuthenticationCredentials(username, password);
    }

    private static boolean hasTotpEnabled(AuthenticationMethod authMethod) {
        if (authMethod == null) {
            return true;
        }

        return isTotpCredentials(authMethod.createAuthenticationCredentials());
    }

    private static boolean isTotpCredentials(AuthenticationCredentials creds) {
        if (tacClass == null) {
            return false;
        }

        try {
            return tacClass.isAssignableFrom(creds.getClass())
                    && (boolean) isTotpEnabledMethod.invoke(creds);

        } catch (Exception e) {
            LOGGER.warn("An error occurred while checking if TOTP enabled credentials:", e);
        }
        return false;
    }

    public static GenericAuthenticationCredentials createGenericAuthenticationCredentials(
            String[] credentialsParamNames) {
        if (genericCredentialsConstructor != null) {
            try {
                return genericCredentialsConstructor.newInstance(credentialsParamNames, true);
            } catch (Exception e) {
                LOGGER.warn("An error occurred while creating TOTP enabled credentials:", e);
            }
        }
        return new GenericAuthenticationCredentials(credentialsParamNames);
    }

    public static void setTotpGenerator(TotpGenerator generator) {
        if (setTotpGeneratorMethod == null) {
            return;
        }

        try {
            if (generator != null) {
                InvocationHandler invocationHandler =
                        (o, method, args) -> {
                            switch (method.getName()) {
                                case "generate":
                                    return generator.generate(
                                            convertData(args[0]), (Instant) args[1]);

                                case "getSupportedAlgorithms":
                                    return generator.getSupportedAlgorithms();

                                default:
                                    return null;
                            }
                        };

                setTotpGeneratorMethod.invoke(
                        null,
                        Proxy.newProxyInstance(
                                TotpSupport.class.getClassLoader(),
                                new Class<?>[] {totpGeneratorClass},
                                invocationHandler));
            } else {
                setTotpGeneratorMethod.invoke(null, (Object) null);
            }

        } catch (Exception e) {
            LOGGER.warn("An error occurred while setting the generator:", e);
        }
    }

    private static TotpData convertData(Object coreData) {
        try {
            return new TotpData(
                    (String) secretMethod.invoke(coreData),
                    (int) periodMethod.invoke(coreData),
                    (int) digitsMethod.invoke(coreData),
                    (String) algorithmMethod.invoke(coreData));

        } catch (Exception e) {
            LOGGER.warn("An error occurred while convert the TOTP data:", e);
        }
        return null;
    }

    public static record TotpData(String secret, int period, int digits, String algorithm) {}

    public interface TotpGenerator {

        String generate(TotpData data, Instant when);

        List<String> getSupportedAlgorithms();
    }

    public static TotpData getTotpData(AuthenticationCredentials credentials) {
        if (!hasTotpSecret(credentials)) {
            return null;
        }

        try {
            return convertData(getTotpCoreData(credentials));
        } catch (Exception e) {
            LOGGER.warn("An error occurred while getting the TOTP data:", e);
        }
        return null;
    }
}
