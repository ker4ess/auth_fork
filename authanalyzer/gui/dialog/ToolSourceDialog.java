package com.protect7.authanalyzer.gui.dialog;

import java.awt.Component;
import java.awt.GridLayout;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JDialog;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.WindowConstants;
import javax.swing.border.EmptyBorder;
import com.protect7.authanalyzer.filter.ToolSourceFilter;

public class ToolSourceDialog extends JDialog {
	
	private static final long serialVersionUID = 1L;
	private final ToolSourceFilter filter;
	private final List<JCheckBox> checkBoxes = new ArrayList<>();
	
	public ToolSourceDialog(Component parent, ToolSourceFilter filter) {
		this.filter = filter;
		setTitle("Select Request Sources");
		
		JPanel dialogPanel = (JPanel) getContentPane();
		dialogPanel.setBorder(new EmptyBorder(10, 10, 10, 10));
		dialogPanel.setLayout(new GridLayout(0, 1, 5, 5));
		
		JLabel infoLabel = new JLabel("<html>Select which request sources should be analyzed:<br></html>");
		dialogPanel.add(infoLabel);
		
		// Получаем список всех доступных инструментов
		List<String> allTools = filter.getAllAvailableTools();
		String[] selectedTools = filter.getFilterStringLiterals();
		List<String> selectedToolsList = selectedTools != null ? Arrays.asList(selectedTools) : new ArrayList<>();
		
		// Создаем чекбоксы для каждого инструмента
		for(String tool : allTools) {
			JCheckBox checkBox = new JCheckBox(tool);
			checkBox.setSelected(selectedToolsList.contains(tool));
			checkBoxes.add(checkBox);
			dialogPanel.add(checkBox);
		}
		
		// Кнопки Select All и Deselect All
		JPanel buttonPanel = new JPanel(new GridLayout(1, 3, 5, 5));
		JButton selectAllButton = new JButton("Select All");
		selectAllButton.addActionListener(e -> {
			for(JCheckBox cb : checkBoxes) {
				cb.setSelected(true);
			}
		});
		
		JButton deselectAllButton = new JButton("Deselect All");
		deselectAllButton.addActionListener(e -> {
			for(JCheckBox cb : checkBoxes) {
				cb.setSelected(false);
			}
		});
		
		JButton okButton = new JButton("OK");
		okButton.addActionListener(e -> {
			saveSelection();
		});
		
		buttonPanel.add(selectAllButton);
		buttonPanel.add(deselectAllButton);
		buttonPanel.add(okButton);
		dialogPanel.add(buttonPanel);
		
		setDefaultCloseOperation(WindowConstants.DISPOSE_ON_CLOSE);
		setModal(true);
		pack();
		setLocationRelativeTo(parent);
		setVisible(true);
	}
	
	private void saveSelection() {
		List<String> selectedTools = new ArrayList<>();
		for(JCheckBox checkBox : checkBoxes) {
			if(checkBox.isSelected()) {
				selectedTools.add(checkBox.getText());
			}
		}
		if(selectedTools.isEmpty()) {
			int result = javax.swing.JOptionPane.showConfirmDialog(
				this,
				"No request sources selected. All requests will be filtered.\n\nDo you want to continue?",
				"Warning",
				javax.swing.JOptionPane.YES_NO_OPTION,
				javax.swing.JOptionPane.WARNING_MESSAGE
			);
			if(result != javax.swing.JOptionPane.YES_OPTION) {
				return; // Отменяем закрытие диалога
			}
		}
		filter.setFilterStringLiterals(selectedTools.toArray(new String[0]));
		// Обновляем подсказку после сохранения
		filter.updateHint();
		dispose();
	}
}

