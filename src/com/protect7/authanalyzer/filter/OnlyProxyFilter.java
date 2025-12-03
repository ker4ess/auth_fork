package com.protect7.authanalyzer.filter;

import burp.IBurpExtenderCallbacks;
import burp.IRequestInfo;
import burp.IResponseInfo;

public class OnlyProxyFilter extends RequestFilter {

	public OnlyProxyFilter(int filterIndex, String description) {
		super(filterIndex, description);
	}

	@Override
	public boolean filterRequest(IBurpExtenderCallbacks callbacks, int toolFlag, IRequestInfo requestInfo, IResponseInfo responseInfo) {
		if(onOffButton.isSelected()) {
			// Если фильтр включен - разрешаем только Proxy, остальное фильтруем
			if(toolFlag == IBurpExtenderCallbacks.TOOL_PROXY) {
				return false; // Не фильтруем Proxy
			}
			// Все остальное фильтруем
			incrementFiltered();
			return true;
		}
		else {
			// Если фильтр выключен - не фильтруем ничего (разрешаем все)
			return false;
		}
	}

	@Override
	public boolean hasStringLiterals() {
		return false;
	}
}