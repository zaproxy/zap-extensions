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
package org.zaproxy.addon.paramdigger;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.locks.Condition;
import java.util.concurrent.locks.ReentrantLock;
import org.apache.commons.lang.time.StopWatch;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.network.HttpSender;

public class ParamGuesser implements Runnable {
    private int id;
    private volatile boolean paused = false;
    private volatile boolean stopped = false;
    private ReentrantLock pauseLock = new ReentrantLock();
    private Condition pausedCondition = pauseLock.newCondition();
    private ExecutorService executor;

    private HttpSender httpSender;
    private static final Logger logger = LogManager.getLogger(ParamGuesser.class);

    private UrlGuesser urlGuesser;
    private HeaderGuesser headerGuesser;
    private CookieGuesser cookieGuesser;

    private StopWatch stopWatch;
    private boolean stopWatchStarted;
    private GuesserScan scan;
    private ParamDiggerConfig config;

    public ParamGuesser(int id, GuesserScan scan, ExecutorService executor) {
        this.id = id;
        this.scan = scan;
        this.executor = executor;
        this.config = scan.getConfig();
        // TODO - use the actual core initiator once targeting >= 2.12.0
        httpSender =
                new HttpSender(
                        Model.getSingleton().getOptionsParam().getConnectionParam(), true, 17);
        if (config.doUrlGuess()) {
            urlGuesser = new UrlGuesser(id, scan, httpSender, executor);
        }
        if (config.doHeaderGuess()) {
            headerGuesser = new HeaderGuesser(id, scan, httpSender, executor);
        }
        if (config.doCookieGuess()) {
            cookieGuesser = new CookieGuesser(id, scan, httpSender, executor);
        }
    }

    @Override
    public void run() {
        logger.debug("Starting param guesser ...");
        if (stopWatch == null) {
            stopWatch = new StopWatch();
        }
        if (!stopWatchStarted) {
            stopWatch.start();
            stopWatchStarted = true;
        }

        if (this.scan.isStopped()) {
            return;
        }

        if (config.doUrlGuess()) {
            this.executor.submit(urlGuesser);
        }
        if (config.doHeaderGuess()) {
            this.executor.submit(headerGuesser);
        }
        if (config.doCookieGuess()) {
            this.executor.submit(cookieGuesser);
        }
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

        this.executor.shutdown();
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
                                if (executor != null) {
                                    executor.shutdown();
                                }
                                reset();
                                executor = null;
                            }
                        },
                        "ZAP-ParamGuesserShutdownThread-" + id)
                .start();
    }

    private void reset() {
        // TODO add reset code here
    }
}
