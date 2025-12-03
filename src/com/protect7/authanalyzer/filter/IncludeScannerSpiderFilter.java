package com.protect7.authanalyzer.filter;

import burp.IBurpExtenderCallbacks;
import burp.IRequestInfo;
import burp.IResponseInfo;

public class IncludeScannerSpiderFilter extends RequestFilter {

	public IncludeScannerSpiderFilter(int filterIndex, String description) {
		super(filterIndex, description);
	}

	@Override
	public boolean filterRequest(IBurpExtenderCallbacks callbacks, int toolFlag, IRequestInfo requestInfo, IResponseInfo responseInfo) {
		if(onOffButton.isSelected()) {
			// Если чекбокс включен, НЕ фильтруем Scanner и Spider
			if(toolFlag == IBurpExtenderCallbacks.TOOL_SCANNER || toolFlag == IBurpExtenderCallbacks.TOOL_SPIDER) {
				return false; // Разрешаем Scanner и Spider
			}
		}
		// Не фильтруем остальные (оставляем решение другим фильтрам)
		return false;
	}

	@Override
	public boolean hasStringLiterals() {
		return false;
	}
}

