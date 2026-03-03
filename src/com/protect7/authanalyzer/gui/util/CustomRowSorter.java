package com.protect7.authanalyzer.gui.util;

import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
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
						String path = entry.getStringValue(3).toString();
						String pattern = filterText.getText();
						boolean contained = pathContains(path, pattern);
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

	/** Full-text search in raw bytes: tries pattern in multiple encodings (ASCII, UTF-8, Cyrillic, etc.). */
	private static boolean containsBytes(byte[] bytes, String pattern) {
		if (pattern == null || pattern.isEmpty() || bytes == null || bytes.length == 0) return false;
		for (byte[] needle : getPatternBytesInEncodings(pattern)) {
			if (needle.length == 0) continue;
			if (indexOf(bytes, needle) >= 0) return true;
		}
		return false;
	}

	private static int indexOf(byte[] haystack, byte[] needle) {
		for (int i = 0; i <= haystack.length - needle.length; i++) {
			boolean match = true;
			for (int j = 0; j < needle.length; j++) {
				if (haystack[i + j] != needle[j]) { match = false; break; }
			}
			if (match) return i;
		}
		return -1;
	}

	private static final Charset[] SEARCH_CHARSETS = new Charset[] {
		StandardCharsets.UTF_8,
		StandardCharsets.ISO_8859_1,
		charsetOrNull("windows-1251"),
		charsetOrNull("windows-1252"),
		charsetOrNull("cp866"),
		StandardCharsets.US_ASCII
	};

	private static Charset charsetOrNull(String name) {
		try { return Charset.forName(name); } catch (Exception e) { return null; }
	}

	private static List<byte[]> getPatternBytesInEncodings(String pattern) {
		List<byte[]> result = new ArrayList<>();
		for (Charset cs : SEARCH_CHARSETS) {
			if (cs == null) continue;
			try {
				byte[] encoded = pattern.getBytes(cs);
				if (encoded.length > 0) result.add(encoded);
			} catch (Exception ignored) { }
		}
		return result;
	}

	/** Path search: literal match and URL-encoded match (for any script/special chars). */
	private static boolean pathContains(String path, String pattern) {
		if (path == null || pattern == null) return false;
		if (path.contains(pattern)) return true;
		try {
			String encoded = URLEncoder.encode(pattern, StandardCharsets.UTF_8.name());
			if (path.contains(encoded)) return true;
		} catch (UnsupportedEncodingException ignored) { }
		return false;
	}
}
