/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2020 The ZAP Development Team
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
package org.zaproxy.zap.extension.jwt.attacks;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.function.Predicate;
import java.util.function.Supplier;
import org.apache.log4j.Logger;
import org.zaproxy.zap.extension.jwt.JWTActiveScanner;
import org.zaproxy.zap.extension.jwt.JWTConfiguration;

/**
 * @author preetkaran20@gmail.com KSASAN
 * @since TODO add version
 * @param <T>
 */
public class GenericAsyncTaskExecutor<T> {

    private Predicate<T> predicate;
    private Iterator<T> iterator;
    private ExecutorService executorService;
    private JWTActiveScanner jwtActiveScanner;
    private boolean isAttackSuccessful = false;

    private static final Logger LOGGER = Logger.getLogger(GenericAsyncTaskExecutor.class);

    public GenericAsyncTaskExecutor(
            Predicate<T> predicate, Iterator<T> iterator, JWTActiveScanner jwtActiveScanner) {
        this.predicate = predicate;
        this.iterator = iterator;
        executorService = JWTConfiguration.getInstance().getExecutorService();
        this.jwtActiveScanner = jwtActiveScanner;
    }

    private CompletableFuture<Void> executeTaskAsync(T value) {
        Supplier<Void> attackTask =
                () -> {
                    if (isStop()) {
                        return null;
                    }
                    isAttackSuccessful = predicate.test(value);
                    return null;
                };
        return CompletableFuture.supplyAsync(attackTask, this.executorService);
    }

    private boolean isStop() {
        if (isAttackSuccessful || this.jwtActiveScanner.isStop()) {
            LOGGER.info(
                    "Stopping because either attack is successful or user has manually stopped the execution");
            return true;
        }
        return false;
    }

    private void waitForCompletion(List<CompletableFuture<?>> completableFutures) {
        try {
            CompletableFuture.allOf(
                            completableFutures.toArray(
                                    new CompletableFuture<?>[completableFutures.size()]))
                    .get(500, TimeUnit.SECONDS);
        } catch (InterruptedException | ExecutionException | TimeoutException e) {
            LOGGER.error("Error occurred while executing bruteforce attack", e);
        } finally {
            completableFutures.clear();
        }
    }

    public boolean execute() {
        if (isStop()) {
            return isAttackSuccessful;
        }
        if (iterator != null) {
            List<CompletableFuture<?>> completableFutures = new ArrayList<>();
            while (iterator.hasNext()) {
                T value = iterator.next();
                if (!isStop()) {
                    completableFutures.add(this.executeTaskAsync(value));
                }
            }
            waitForCompletion(completableFutures);
        }
        return isAttackSuccessful;
    }
}
