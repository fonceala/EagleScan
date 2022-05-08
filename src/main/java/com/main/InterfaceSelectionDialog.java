package com.main;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

public class InterfaceSelectionDialog {
    private static JDialog dialog;

    InterfaceSelectionDialog(JFrame frame){
        dialog = new JDialog(frame,"Attention!",true);
        dialog.setLayout(new FlowLayout());
        JButton okButton = new JButton("Ok!");
        okButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent actionEvent) {
                InterfaceSelectionDialog.dialog.setVisible(false);
            }
        });

        dialog.add(new JLabel("Please select an interface first!"));
        dialog.add(okButton);
        dialog.setSize(300,100);
        dialog.setLocationRelativeTo(null);
        dialog.setVisible(true);
    }
}
