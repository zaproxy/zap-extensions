/*
 * Zed Attack Proxy (ZAP) and its related class files.
 * 
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 * 
 * Copyright 2010 psiinon@gmail.com
 * 
 * Licensed under the Apache License, Version 2.0 (the "License"); 
 * you may not use this file except in compliance with the License. 
 * You may obtain a copy of the License at 
 * 
 *   http://www.apache.org/licenses/LICENSE-2.0 
 *   
 * Unless required by applicable law or agreed to in writing, software 
 * distributed under the License is distributed on an "AS IS" BASIS, 
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. 
 * See the License for the specific language governing permissions and 
 * limitations under the License. 
 */
package org.zaproxy.zap.extension.multiFuzz;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;

import org.apache.log4j.Logger;
import org.owasp.jbrofuzz.core.Fuzzer;
import org.parosproxy.paros.common.ThreadPool;

public class FuzzerThread implements Runnable {

	private static final Logger log = Logger.getLogger(FuzzerThread.class);

	private List<FuzzerListener> listenerList = new ArrayList<>();
	private ArrayList<FuzzGap> gaps;

	FuzzProcessFactory fuzzProcessFactory;

	private boolean pause = false;
	private boolean isStop = false;

	private ThreadPool pool = null;
	private int delayInMs = 0;

	public FuzzerThread(FuzzerParam fuzzerParam) {
		pool = new ThreadPool(fuzzerParam.getThreadPerScan());
		delayInMs = fuzzerParam.getDelayInMs();
	}

	public void start() {
		isStop = false;
		Thread thread = new Thread(this, "ZAP-FuzzerThread");
		thread.setPriority(Thread.NORM_PRIORITY-2);
		thread.start();
	}

	public void stop() {
		isStop = true;
	}

	public void addFuzzerListener(FuzzerListener listener) {
		listenerList.add(listener);		
	}

	public void removeFuzzerListener(FuzzerListener listener) {
		listenerList.remove(listener);
	}

	private void notifyFuzzerComplete() {
		for (FuzzerListener listener : listenerList) {
			listener.notifyFuzzerComplete();
		}
	}

	public void setTarget(ArrayList<FuzzGap> gaps, FuzzProcessFactory fuzzProcessFactory) {
		this.gaps = gaps;
		this.fuzzProcessFactory = fuzzProcessFactory;
	}

	@Override
	public void run() {
		log.info("fuzzer started");

		this.fuzz(gaps);

		pool.waitAllThreadComplete(0);
		notifyFuzzerComplete();

		log.info("fuzzer stopped");
	}

	private void fuzz(ArrayList<FuzzGap> gaps) {
		int total = 1;
		int[] lens = new int[gaps.size()]; 
		for(int i = 0; i < gaps.size(); i++){
			int subtotal = 0;
			for(Fuzzer f : gaps.get(i).getFuzzers()){
				subtotal += (int)f.getMaximumValue();
			}
			for(FileFuzzer f : gaps.get(i).getFileFuzzers()){
				subtotal += (int)f.getLength();
			}
			total *= subtotal;
			lens[i] = subtotal;
		}
		
		int[] mod = new int[gaps.size()];
		for(int i = 0; i < mod.length; i++){
			mod[i] = 1;
		}
		for(int i = lens.length - 1; i >= 0; i --){
			for(int j = 0; j < i; j++){
				mod[j] *= lens[i];
			}
		}

		for (FuzzerListener listener : listenerList) {
			listener.notifyFuzzerStarted(total);
		}

		for (int nr = 0; nr < total; nr++) {
			HashMap<FuzzLocation, String> subs = new HashMap<FuzzLocation,String>();
			for(int g = 0; g < gaps.size(); g++){
				FuzzLocation fl = gaps.get(g).getFuzzLoc();
				String sub = gaps.get(g).getSubstitution((nr/mod[g]) % lens[g]);
				subs.put(fl, sub);
			}
			fuzz(subs);
			if (isStop()) {
				break;
			}
		}
	}

	private void fuzz(HashMap<FuzzLocation,String> subs) {
		while (pause && ! isStop()) {
			try {
				Thread.sleep(500);
			} catch (InterruptedException e) {
				// Ignore
			}
		}

		if (delayInMs > 0) {
			try {
				Thread.sleep(delayInMs);
			} catch (InterruptedException e) {
				// Ignore
			}
		}

		FuzzProcess fp = fuzzProcessFactory.getFuzzProcess(subs);

		for (FuzzerListener listener : listenerList) {
			fp.addFuzzerListener(listener);
		}

		Thread thread;
		do { 
			thread = pool.getFreeThreadAndRun(fp);
			if (thread == null) {
				try {
					Thread.sleep(500);
				} catch (InterruptedException e) {
					// Ignore
				}
			}
		} while (thread == null && !isStop());

	}

	public boolean isStop() {
		return isStop;
	}

	public void pause() {
		this.pause = true;
	}

	public void resume () {
		this.pause = false;
	}

	public boolean isPaused() {
		return pause;
	}

}
