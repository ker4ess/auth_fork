package com.protect7.authanalyzer.filter;

import java.util.Arrays;
import java.util.List;
import com.protect7.authanalyzer.util.GenericHelper;
import burp.IBurpExtenderCallbacks;
import burp.IRequestInfo;
import burp.IResponseInfo;

public class ToolSourceFilter extends RequestFilter {
	
	private static final String TOOL_PROXY = "Proxy";
	private static final String TOOL_REPEATER = "Repeater";
	private static final String TOOL_INTRUDER = "Intruder";
	private static final String TOOL_SCANNER = "Scanner";
	private static final String TOOL_SPIDER = "Spider";
	private static final String TOOL_SEQUENCER = "Sequencer";
	private static final String TOOL_EXTENDER = "Extender";
	private static final String TOOL_TARGET = "Target";
	private static final String TOOL_COMPARER = "Comparer";
	
	public ToolSourceFilter(int filterIndex, String description) {
		super(filterIndex, description);
		// По умолчанию выбираем все источники
		setFilterStringLiterals(new String[]{
			TOOL_PROXY, TOOL_REPEATER, TOOL_INTRUDER, TOOL_SCANNER, 
			TOOL_SPIDER, TOOL_SEQUENCER, TOOL_EXTENDER, TOOL_TARGET,
			TOOL_COMPARER
		});
	}
	
	@Override
	public String getInfoText() {
		if (onOffButton != null) {
			if (hasStringLiterals() && stringLiterals != null && stringLiterals.length > 0) {
				String selectedTools = GenericHelper.getArrayAsString(stringLiterals);
				return "<html>" + getDescription() + "<br><strong><em>Selected: " + selectedTools + "</em></strong></html>";
			} else {
				return getDescription() + "<br><strong><em>No sources selected</em></strong>";
			}
		}
		return "";
	}

	@Override
	public boolean filterRequest(IBurpExtenderCallbacks callbacks, int toolFlag, IRequestInfo requestInfo, IResponseInfo responseInfo) {
		if(onOffButton.isSelected()) {
			// Если ни один источник не выбран, фильтруем все запросы
			if(stringLiterals == null || stringLiterals.length == 0) {
				incrementFiltered();
				return true;
			}
			// Проверяем, разрешен ли этот источник
			String toolName = getToolName(toolFlag);
			if(toolName != null && isToolAllowed(toolName)) {
				return false; // Не фильтруем, если источник разрешен
			}
			// Фильтруем, если источник не разрешен или неизвестен
			incrementFiltered();
			return true;
		}
		return false; // Если фильтр выключен, не фильтруем
	}
	
	private String getToolName(int toolFlag) {
		if(toolFlag == IBurpExtenderCallbacks.TOOL_PROXY) {
			return TOOL_PROXY;
		} else if(toolFlag == IBurpExtenderCallbacks.TOOL_REPEATER) {
			return TOOL_REPEATER;
		} else if(toolFlag == IBurpExtenderCallbacks.TOOL_INTRUDER) {
			return TOOL_INTRUDER;
		} else if(toolFlag == IBurpExtenderCallbacks.TOOL_SCANNER) {
			return TOOL_SCANNER;
		} else if(toolFlag == IBurpExtenderCallbacks.TOOL_SPIDER) {
			return TOOL_SPIDER;
		} else if(toolFlag == IBurpExtenderCallbacks.TOOL_SEQUENCER) {
			return TOOL_SEQUENCER;
		} else if(toolFlag == IBurpExtenderCallbacks.TOOL_EXTENDER) {
			return TOOL_EXTENDER;
		} else if(toolFlag == IBurpExtenderCallbacks.TOOL_TARGET) {
			return TOOL_TARGET;
		} else if(toolFlag == IBurpExtenderCallbacks.TOOL_COMPARER) {
			return TOOL_COMPARER;
		}
		return null;
	}
	
	private boolean isToolAllowed(String toolName) {
		if(stringLiterals == null) {
			return true; // Если список пуст, разрешаем все
		}
		for(String allowedTool : stringLiterals) {
			if(allowedTool != null && allowedTool.equals(toolName)) {
				return true;
			}
		}
		return false;
	}
	
	public List<String> getAllAvailableTools() {
		return Arrays.asList(
			TOOL_PROXY, TOOL_REPEATER, TOOL_INTRUDER, TOOL_SCANNER,
			TOOL_SPIDER, TOOL_SEQUENCER, TOOL_EXTENDER, TOOL_TARGET,
			TOOL_COMPARER
		);
	}

	@Override
	public boolean hasStringLiterals() {
		return true;
	}
}
