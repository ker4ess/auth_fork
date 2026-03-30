package com.protect7.authanalyzer.util;

import java.util.ArrayList;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import com.protect7.authanalyzer.controller.RequestController;
import com.protect7.authanalyzer.entities.Session;
import com.protect7.authanalyzer.entities.Token;
import com.protect7.authanalyzer.filter.RequestFilter;
import com.protect7.authanalyzer.gui.util.RequestTableModel;

import burp.BurpExtender;
import burp.IHttpRequestResponse;

public class CurrentConfig {

	private static CurrentConfig mInstance = new CurrentConfig();
	//private final String[] patternsStatic = {"token", "code", "user", "mail", "pass", "key", "csrf", "xsrf"};
	//private final String[] patternsDynamic = {"viewstate", "eventvalidation"};
	private final int POOL_SIZE_MIN = 1; 
	private final RequestController requestController = new RequestController();
	private ThreadPoolExecutor analyzerThreadExecutor = createAnalyzerExecutor(POOL_SIZE_MIN, 500);
	private volatile long lastQueueFullLogMs = 0L;
	private ArrayList<RequestFilter> requestFilterList = new ArrayList<>();
	private ArrayList<Session> sessions = new ArrayList<>();
	private RequestTableModel tableModel = null;
	private boolean running = false;
	private boolean dropOriginal = false;
	private volatile int mapId = 0;
	private boolean respectResponseCodeForSameStatus = true;
	private boolean respectResponseCodeForSimilarStatus = true; 
	private int deviationForSimilarStatus = 5;
	private long delayBetweenRequestsInMilliseconds = 0;

	private CurrentConfig() {
	}

	private static ThreadPoolExecutor createAnalyzerExecutor(int threads, int queueCapacity) {
		int cap = Math.max(1, queueCapacity);
		int t = Math.max(1, threads);
		AtomicInteger seq = new AtomicInteger(1);
		return new ThreadPoolExecutor(t, t, 0L, TimeUnit.MILLISECONDS, new ArrayBlockingQueue<>(cap), r -> {
			Thread th = new Thread(r, "AuthAnalyzer-" + seq.getAndIncrement());
			th.setDaemon(true);
			return th;
		}, new ThreadPoolExecutor.AbortPolicy());
	}
	
	public void performAuthAnalyzerRequest(IHttpRequestResponse messageInfo) {
		Runnable task = new Runnable() {				
			@Override
			public void run() {
				BurpExtender.mainPanel.getCenterPanel().updateAmountOfPendingRequests(
						analyzerThreadExecutor.getQueue().size() + analyzerThreadExecutor.getActiveCount());
				getRequestController().analyze(messageInfo);
				try {
					Thread.sleep(delayBetweenRequestsInMilliseconds);
				} catch (InterruptedException e) {
					Thread.currentThread().interrupt();
				}
				BurpExtender.mainPanel.getCenterPanel().updateAmountOfPendingRequests(
						analyzerThreadExecutor.getQueue().size() + analyzerThreadExecutor.getActiveCount());
			}
		};
		try {
			analyzerThreadExecutor.execute(task);
			BurpExtender.mainPanel.getCenterPanel().updateAmountOfPendingRequests(
					analyzerThreadExecutor.getQueue().size() + analyzerThreadExecutor.getActiveCount());
		} catch (RejectedExecutionException e) {
			long now = System.currentTimeMillis();
			if (now - lastQueueFullLogMs > 5000L) {
				lastQueueFullLogMs = now;
				BurpExtender.callbacks.printError(
						"Auth Analyzer: analysis queue is full; dropping traffic until the backlog shrinks. "
								+ "Increase \"" + Setting.Item.ANALYSIS_QUEUE_CAPACITY.getDescription() + "\" in settings if needed.");
			}
		}
	}
	
	public static CurrentConfig getCurrentConfig(){
		  return mInstance;
	}
	
	public void addRequestFilter(RequestFilter requestFilter) {
		getRequestFilterList().add(requestFilter);
	}

	public boolean isRunning() {
		return running;
	}

	public void setRunning(boolean running) {
		if(running) {
			respectResponseCodeForSameStatus = Setting.getValueAsBoolean(Setting.Item.STATUS_SAME_RESPONSE_CODE);
			respectResponseCodeForSimilarStatus = Setting.getValueAsBoolean(Setting.Item.STATUS_SIMILAR_RESPONSE_CODE);
			deviationForSimilarStatus = Setting.getValueAsInteger(Setting.Item.STATUS_SIMILAR_RESPONSE_LENGTH);
			delayBetweenRequestsInMilliseconds = Setting.getValueAsInteger(Setting.Item.DELAY_BETWEEN_REQUESTS);
			int queueCapacity = Setting.getValueAsInteger(Setting.Item.ANALYSIS_QUEUE_CAPACITY);
			if (queueCapacity < 1) {
				queueCapacity = 500;
			}
			if(hasPromptForInput() && Setting.getValueAsBoolean(Setting.Item.ONLY_ONE_THREAD_IF_PROMT_FOR_INPUT)) {
				analyzerThreadExecutor = createAnalyzerExecutor(POOL_SIZE_MIN, queueCapacity);
			}
			else {
				int numberOfThreads = Setting.getValueAsInteger(Setting.Item.NUMBER_OF_THREADS);
				if (numberOfThreads < 1) {
					numberOfThreads = POOL_SIZE_MIN;
				}
				analyzerThreadExecutor = createAnalyzerExecutor(numberOfThreads, queueCapacity);
			}
		}
		else {
			analyzerThreadExecutor.shutdownNow();
			BurpExtender.mainPanel.getCenterPanel().updateAmountOfPendingRequests(0);
		}
		this.running = running;
	}

	private boolean hasPromptForInput() {
		for(Session session : sessions) {
			for(Token token : session.getTokens()) {
				if(token.isPromptForInput()) {
					return true;
				}
			}
		}
		return false;
	}

	public ArrayList<RequestFilter> getRequestFilterList() {
		return requestFilterList;
	}
	
	public RequestFilter getRequestFilterAt(int index) {
		return requestFilterList.get(index);
	}

	public ArrayList<Session> getSessions() {
		return sessions;
	}

	public void addSession(Session session) {
		sessions.add(session);
	}

	public void clearSessionList() {
		sessions.clear();
	}
	
	public int getNextMapId() {
		mapId++;
		return mapId;
	}
	
	public void setDropOriginal(boolean dropOriginal) {
		this.dropOriginal = dropOriginal;
	}
	
	public boolean isDropOriginal() {
		return dropOriginal;
	}
	
	//Returns session with corresponding name. Returns null if session not exists
	public Session getSessionByName(String name) {
		for(Session session : sessions) {
			if(session.getName().equals(name)) {
				return session;
			}
		}
		return null;
	}
	
	public RequestTableModel getTableModel() {
		return tableModel;
	}

	public void setTableModel(RequestTableModel tableModel) {
		this.tableModel = tableModel;
	}
	
	public void clearSessionRequestMaps() {
		for(Session session : getSessions()) {
			session.clearRequestResponseMap();
		}
	}

	public ThreadPoolExecutor getAnalyzerThreadExecutor() {
		return analyzerThreadExecutor;
	}

	public RequestController getRequestController() {
		return requestController;
	}

	public boolean isRespectResponseCodeForSameStatus() {
		return respectResponseCodeForSameStatus;
	}

	public void setRespectResponseCodeForSameStatus(boolean respectResponseCodeForSameStatus) {
		this.respectResponseCodeForSameStatus = respectResponseCodeForSameStatus;
	}

	public boolean isRespectResponseCodeForSimilarStatus() {
		return respectResponseCodeForSimilarStatus;
	}

	public void setRespectResponseCodeForSimilarFlag(boolean respectResponseCodeForSimilarStatus) {
		this.respectResponseCodeForSimilarStatus = respectResponseCodeForSimilarStatus;
	}

	public int getDerivationForSimilarStatus() {
		return deviationForSimilarStatus;
	}

	public void setDerivationForSimilarStatus(int derivationForSimilarStatus) {
		this.deviationForSimilarStatus = derivationForSimilarStatus;
	}	
}