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
			
			// КРИТИЧЕСКИ ВАЖНО: Обрабатываем ТОЛЬКО когда приходит RESPONSE (messageIsRequest = false),
			// потому что для сравнения оригинального и модифицированного запроса нам нужен оригинальный response!
			// Когда приходит response, в messageInfo уже есть и request и response.
			// Если обрабатывать при messageIsRequest = true, то response еще нет, и сравнение невозможно.
			if(!messageIsRequest) {
				// ЛОГИКА ОБРАБОТКИ ЗАПРОСОВ:
				// 1. TOOL_EXTENDER - уже отфильтровано выше (игнорируем)
				// 2. Scanner и Spider - ВСЕГДА обрабатываем (независимо от dropOriginal)
				//    Это критически важно, т.к. пользователь должен видеть оригинальные запросы от Scanner/Spider
				// 3. Если dropOriginal выключен - обрабатываем ВСЕ запросы (включая Proxy)
				// 4. Если dropOriginal включен - обрабатываем только Proxy (для Proxy dropOriginal работает)
				boolean shouldProcess = false;
				
				// Scanner и Spider ВСЕГДА обрабатываем (независимо от dropOriginal)
				if(toolFlag == IBurpExtenderCallbacks.TOOL_SCANNER || toolFlag == IBurpExtenderCallbacks.TOOL_SPIDER) {
					shouldProcess = true;
				}
				// Для остальных инструментов проверяем dropOriginal
				else if(!config.isDropOriginal()) {
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
		}
	}

	@Override
	public void processProxyMessage(boolean messageIsRequest, IInterceptedProxyMessage message) {
		// КРИТИЧЕСКИ ВАЖНО: dropOriginal должен дропать запрос, НО нам нужен response для сравнения!
		// ПРОБЛЕМА: Если мы дропаем запрос здесь (когда messageIsRequest = true), то response не придет,
		// и мы не сможем сравнить оригинальный и модифицированный response в RequestController.
		//
		// РЕШЕНИЕ: НЕ дропать запрос в processProxyMessage, если dropOriginal включен.
		// Вместо этого обрабатывать его в processHttpMessage когда придет response (messageIsRequest = false).
		// dropOriginal в этом случае означает, что мы обрабатываем запрос через расширение,
		// а не через обычный Proxy flow. Оригинальный запрос все равно пройдет через Proxy,
		// получит response, и затем будет обработан расширением для сравнения с модифицированными запросами.
		//
		// ВАЖНО: Оригинальный запрос НЕ дропается, он проходит через Proxy нормально,
		// получает response, и затем обрабатывается расширением для сравнения.
		// Это правильное поведение, т.к. нам нужен оригинальный response для сравнения.
		//
		// ПРИМЕЧАНИЕ: Если пользователь хочет дропать оригинальный запрос в Proxy истории,
		// это можно сделать через другие механизмы Burp, но не через ACTION_DROP здесь,
		// т.к. это помешает получению response для сравнения.
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
