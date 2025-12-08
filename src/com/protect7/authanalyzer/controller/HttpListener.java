package com.protect7.authanalyzer.controller;

import com.protect7.authanalyzer.filter.RequestFilter;
import com.protect7.authanalyzer.util.CurrentConfig;
import burp.BurpExtender;
import burp.IBurpExtenderCallbacks;
import burp.IHttpListener;
import burp.IHttpRequestResponse;
import burp.IInterceptedProxyMessage;
import burp.IProxyListener;
import burp.IRequestInfo;
import burp.IResponseInfo;

public class HttpListener implements IHttpListener, IProxyListener {

	private final CurrentConfig config = CurrentConfig.getCurrentConfig();

	@Override
	public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {
		if(config.isRunning()) {
			// КРИТИЧЕСКИ ВАЖНО: Игнорируем запросы с TOOL_EXTENDER - это запросы, сгенерированные
			// самим расширением через makeHttpRequest. Обрабатывать их снова нельзя, иначе будет
			// рекурсивное дублирование (экспоненциальный рост запросов)!
			if(toolFlag == IBurpExtenderCallbacks.TOOL_EXTENDER) {
				return; // НЕ обрабатываем запросы, созданные расширением
			}
			
			// Обрабатываем ТОЛЬКО запросы, чтобы избежать дублирования
			// Ответы уже будут в messageInfo когда обрабатывается запрос с ответом
			if(messageIsRequest) {
				// ЛОГИКА ОБРАБОТКИ ЗАПРОСОВ:
				// 1. TOOL_EXTENDER - уже отфильтровано выше (игнорируем)
				// 2. Если dropOriginal выключен - обрабатываем ВСЕ запросы (Scanner, Spider, Proxy и т.д.)
				// 3. Если dropOriginal включен - обрабатываем ТОЛЬКО Proxy запросы
				//    (Scanner/Spider в этом случае не обрабатываются, т.к. они не проходят через Proxy)
				boolean shouldProcess = false;
				if(!config.isDropOriginal()) {
					// dropOriginal выключен - обрабатываем все запросы от любых инструментов
					shouldProcess = true;
				} else {
					// dropOriginal включен - обрабатываем только Proxy
					if(toolFlag == IBurpExtenderCallbacks.TOOL_PROXY) {
						shouldProcess = true;
					}
				}
				
				if(shouldProcess && !isFiltered(toolFlag, messageInfo)) {
					config.performAuthAnalyzerRequest(messageInfo);
				}
			}
			// Ответы не обрабатываем отдельно - они уже включены в messageInfo при обработке запроса
		}
	}

	@Override
	public void processProxyMessage(boolean messageIsRequest, IInterceptedProxyMessage message) {
		if(config.isDropOriginal() && messageIsRequest) {
			if(!isFiltered(IBurpExtenderCallbacks.TOOL_PROXY, message.getMessageInfo())) {
				processHttpMessage(IBurpExtenderCallbacks.TOOL_PROXY, true, message.getMessageInfo());
				message.setInterceptAction(IInterceptedProxyMessage.ACTION_DROP);
			}
		}
	}
	
	private boolean isFiltered(int toolFlag, IHttpRequestResponse messageInfo) {
		boolean isFiltered = false;
		IRequestInfo requestInfo = BurpExtender.callbacks.getHelpers().analyzeRequest(messageInfo);
		IResponseInfo responseInfo = null;
		if(messageInfo.getResponse() != null) {
			responseInfo = BurpExtender.callbacks.getHelpers().analyzeResponse(messageInfo.getResponse());
		}
		for(int i=0; i<config.getRequestFilterList().size(); i++) {
			RequestFilter filter = config.getRequestFilterAt(i);
			if(filter.filterRequest(BurpExtender.callbacks, toolFlag, requestInfo, responseInfo)) {
				return true;
			}
		}
		return isFiltered;
	}
}
