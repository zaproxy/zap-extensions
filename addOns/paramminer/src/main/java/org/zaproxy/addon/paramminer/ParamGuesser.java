/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2022 The ZAP Development Team
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
package org.zaproxy.addon.paramminer;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.locks.Condition;
import java.util.concurrent.locks.ReentrantLock;
import org.apache.commons.lang.time.StopWatch;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpSender;

public class ParamGuesser {
    private String id;
    private ExtensionParamMiner extension;
    private volatile boolean paused = false;
    private volatile boolean stopped = false;
    private ReentrantLock pauseLock = new ReentrantLock();
    private Condition pausedCondition = pauseLock.newCondition();
    private ExecutorService threadPool;

    private HttpSender httpSender;
    private static final Logger logger = LogManager.getLogger(ParamGuesser.class);

    private UrlGuesser urlGuesser;
    private HeaderGuesser headerGuesser;
    private CookieGuesser cookieGuesser;
    private ParamMinerConfig guesserConfig;
    int tasksDoneCount;
    int tasksTodoCount;
    private StopWatch stopWatch;
    private boolean stopWatchStarted;
    private HttpMessage seed;

    public ParamGuesser(
            String id,
            ExtensionParamMiner extension,
            HttpMessage seed,
            ParamMinerConfig guesserData) {
        this.id = id;
        this.extension = extension;
        this.seed = seed;
        this.guesserConfig = guesserData;
    }

    public void setSeedHttpMessage(HttpMessage seed) {
        this.seed = seed;
    }

    public HttpMessage getSeedHttpMessage() {
        return seed;
    }

    public void start() {
        logger.debug("Starting param guesser ...");
        if (stopWatch == null) {
            stopWatch = new StopWatch();
        }
        if (!stopWatchStarted) {
            stopWatch.start();
            stopWatchStarted = true;
        }
        this.threadPool =
                Executors.newFixedThreadPool(
                        guesserConfig.getThreadpoolSize(),
                        new ParamGuesserThreadFactory(
                                "ZAP-ParamGuesserThreadPool-" + id + "-thread-"));

        // TODO - use the actual core initiator once targeting >= 2.12.0
        httpSender =
                new HttpSender(
                        Model.getSingleton().getOptionsParam().getConnectionParam(), true, 17);
        httpSender.setFollowRedirect(guesserConfig.getRedirectState());
    }

    public void stop() {
        stopped = true;
        stopWatch.stop();
        if (stopped) {
            return;
        }
        this.stopped = true;
        logger.debug("Stopping guessing process by request.");

        if (this.paused) {
            this.resume();
        }

        this.threadPool.shutdown();
    }

    public ExtensionParamMiner getExtensionParamMiner() {
        return this.extension;
    }

    public void resume() {
        paused = false;
        pauseLock.lock();
        try {
            pausedCondition.signalAll();
        } finally {
            pauseLock.unlock();
        }
    }

    public void pause() {
        pauseLock.lock();
        try {
            paused = true;
        } finally {
            pauseLock.unlock();
        }
    }

    public void complete() {
        if (stopped) {
            return;
        }
        logger.debug("Guessing process is complete. Shutting Down ... ");
        this.stopped = true;
        stopWatch.stop();
        if (httpSender != null) {
            httpSender.shutdown();
            httpSender = null;
        }
        reset();

        new Thread(
                        new Runnable() {
                            @Override
                            public void run() {
                                if (threadPool != null) {
                                    threadPool.shutdown();
                                }
                                reset();
                                threadPool = null;
                            }
                        },
                        "ZAP-ParamGuesserShutdownThread-" + id)
                .start();
    }

    private void reset() {
        // TODO add reset code here
    }

    private static class ParamGuesserThreadFactory implements ThreadFactory {

        private final AtomicInteger threadNumber;
        private final String namePrefix;
        private final ThreadGroup group;

        public ParamGuesserThreadFactory(String namePrefix) {
            threadNumber = new AtomicInteger(1);
            this.namePrefix = namePrefix;
            group = Thread.currentThread().getThreadGroup();
        }

        @Override
        public Thread newThread(Runnable r) {
            Thread t = new Thread(group, r, namePrefix + threadNumber.getAndIncrement(), 0);
            if (t.isDaemon()) {
                t.setDaemon(false);
            }
            if (t.getPriority() != Thread.NORM_PRIORITY) {
                t.setPriority(Thread.NORM_PRIORITY);
            }
            return t;
        }
    }
}
