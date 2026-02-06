package com.protect7.authanalyzer.gui.util;

import java.nio.charset.StandardCharsets;
import java.util.Collections;
import javax.swing.JCheckBox;
import javax.swing.RowFilter;
import javax.swing.RowSorter;
import javax.swing.SortOrder;
import javax.swing.table.TableRowSorter;
import com.protect7.authanalyzer.entities.AnalyzerRequestResponse;
import com.protect7.authanalyzer.entities.OriginalRequestResponse;
import com.protect7.authanalyzer.entities.Session;
import com.protect7.authanalyzer.gui.main.CenterPanel;
import com.protect7.authanalyzer.util.BypassConstants;
import com.protect7.authanalyzer.util.CurrentConfig;

public class CustomRowSorter extends TableRowSorter<RequestTableModel> {
	
	public CustomRowSorter(CenterPanel centerPanel, RequestTableModel tableModel, JCheckBox showOnlyMarked, JCheckBox showDuplicates, JCheckBox showBypassed, 
			JCheckBox showPotentialBypassed, JCheckBox showNotBypassed, JCheckBox showNA, PlaceholderTextField filterText,
			JCheckBox searchInPath, JCheckBox searchInRequest, JCheckBox searchInResponse, JCheckBox negativeSearch) {
		super(tableModel);
		showOnlyMarked.addActionListener(e -> tableModel.fireTableDataChanged());
		showDuplicates.addActionListener(e -> tableModel.fireTableDataChanged());
		showBypassed.addActionListener(e -> tableModel.fireTableDataChanged());
		showPotentialBypassed.addActionListener(e -> tableModel.fireTableDataChanged());
		showNotBypassed.addActionListener(e -> tableModel.fireTableDataChanged());
		showNA.addActionListener(e -> tableModel.fireTableDataChanged());
		filterText.addActionListener(e -> tableModel.fireTableDataChanged());
		setMaxSortKeys(1);
        setSortKeys(Collections.singletonList(new RowSorter.SortKey(0, SortOrder.DESCENDING)));
		
		
		RowFilter<Object, Object> filter = new RowFilter<Object, Object>() {
			
			public boolean include(Entry<?, ?> entry) {
				if(filterText.getText() != null && !filterText.getText().equals("")) {
					centerPanel.toggleSearchButtonText();
					boolean doShow = false;
					if(searchInPath.isSelected()) {
						boolean contained = entry.getStringValue(3).toString().contains(filterText.getText());
						if((contained && !negativeSearch.isSelected()) || (!contained && negativeSearch.isSelected())) {
							doShow = true;
						}
					}
					if(searchInRequest.isSelected() && !doShow) {
						try {
							int modelRow = (Integer) entry.getIdentifier();
							OriginalRequestResponse original = tableModel.getOriginalRequestResponse(modelRow);
							if(original == null) { /* skip */ } else {
								String pattern = filterText.getText();
								boolean contained = false;
								if(original.getRequestResponse() != null) {
									byte[] bytes = original.getRequestResponse().getRequest();
									if(bytes != null) contained = containsBytes(bytes, pattern);
								}
								if(!contained) {
									int id = original.getId();
									for(Session session : CurrentConfig.getCurrentConfig().getSessions()) {
										AnalyzerRequestResponse arr = session.getRequestResponseMap().get(id);
										if(arr != null && arr.getRequestResponse() != null) {
											byte[] bytes = arr.getRequestResponse().getRequest();
											if(bytes != null && containsBytes(bytes, pattern)) { contained = true; break; }
										}
									}
								}
								if((contained && !negativeSearch.isSelected()) || (!contained && negativeSearch.isSelected())) doShow = true;
							}
						} catch (Exception ignored) { }
					}
					if(searchInResponse.isSelected() && !doShow) {
						try {
							int modelRow = (Integer) entry.getIdentifier();
							OriginalRequestResponse original = tableModel.getOriginalRequestResponse(modelRow);
							if(original == null) { /* skip */ } else {
								String pattern = filterText.getText();
								boolean contained = false;
								if(original.getRequestResponse() != null) {
									byte[] bytes = original.getRequestResponse().getResponse();
									if(bytes != null) contained = containsBytes(bytes, pattern);
								}
								if(!contained) {
									int id = original.getId();
									for(Session session : CurrentConfig.getCurrentConfig().getSessions()) {
										AnalyzerRequestResponse arr = session.getRequestResponseMap().get(id);
										if(arr != null && arr.getRequestResponse() != null) {
											byte[] bytes = arr.getRequestResponse().getResponse();
											if(bytes != null && containsBytes(bytes, pattern)) { contained = true; break; }
										}
									}
								}
								if((contained && !negativeSearch.isSelected()) || (!contained && negativeSearch.isSelected())) doShow = true;
							}
						} catch (Exception ignored) { }
					}
					centerPanel.toggleSearchButtonText();
					if(!doShow && (searchInPath.isSelected() || searchInResponse.isSelected() || searchInRequest.isSelected())) {
						return false;
					}
				}
				if(showOnlyMarked.isSelected()) {
					OriginalRequestResponse requestResponse = tableModel.getOriginalRequestResponseById(Integer.parseInt(entry.getStringValue(0)));
					if(requestResponse != null && !requestResponse.isMarked()) {
						return false;
					}
				}
				if(!showDuplicates.isSelected()) {
					String endpoint = entry.getStringValue(1).toString() + entry.getStringValue(2).toString() 
							+ entry.getStringValue(3).toString();	
					if(tableModel.isDuplicate(Integer.parseInt(entry.getStringValue(0)), endpoint)) {
						return false;
					}
				}
				if(showBypassed.isSelected()) {
					for(int i = entry.getValueCount()-1; i>3; i--) {
						if(entry.getStringValue(i).equals(BypassConstants.SAME.toString())) {
							return true;
						}
					}
				}
				if(showPotentialBypassed.isSelected()) {
					for(int i = entry.getValueCount()-1; i>3; i--) {
						if(entry.getStringValue(i).equals(BypassConstants.SIMILAR.toString())) {
							return true;
						}
					}
				}
				if(showNotBypassed.isSelected()) {
					for(int i = entry.getValueCount()-1; i>3; i--) {
						if(entry.getStringValue(i).equals(BypassConstants.DIFFERENT.toString())) {
							return true;
						}
					}
				}
				if(showNA.isSelected()) {
					for(int i = entry.getValueCount()-1; i>3; i--) {
						if(entry.getStringValue(i).equals(BypassConstants.NA.toString())) {
							return true;
						}
					}
				}
				return false;
			}
		};
		
		setRowFilter(filter);
	}

	private static boolean containsBytes(byte[] bytes, String pattern) {
		if(pattern == null || pattern.isEmpty() || bytes == null || bytes.length == 0) return false;
		byte[] needle = pattern.getBytes(StandardCharsets.UTF_8);
		if(needle.length == 0) return false;
		for(int i = 0; i <= bytes.length - needle.length; i++) {
			boolean match = true;
			for(int j = 0; j < needle.length; j++) {
				if(bytes[i + j] != needle[j]) { match = false; break; }
			}
			if(match) return true;
		}
		return false;
	}
}
