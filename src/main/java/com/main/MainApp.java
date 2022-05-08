package com.main;

import org.pcap4j.core.*;
import org.pcap4j.core.PcapNetworkInterface.*;
import org.pcap4j.packet.*;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.WindowEvent;
import java.awt.event.WindowListener;
import java.io.File;
import java.io.FileWriter;
import java.io.PrintWriter;
import java.net.InetAddress;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.List;
public class MainApp extends JFrame {
    private static PcapNetworkInterface nif;

    private static final Map<InetAddress,List<InetAddress>> accessMap = new HashMap<>();
    private static Map<String,InetAddress> synFloodMap = new HashMap<>();
    private static final MiningPoolAnalyzer miningPoolAnalyzer = new MiningPoolAnalyzer();

    private static boolean RUN = true;

    final static int maxPackets = 1500;
    //main method for capturing the packets
    public static void main(String[] args) {
        JFrame frame = new JFrame("Eagle Scan");
        JPanel panel = new JPanel();

        List<PcapNetworkInterface> nifs = null;
        try {
            nifs = Pcaps.findAllDevs();
        } catch (Exception e) {
            e.printStackTrace();
        }
        String[] nifList = new String[nifs.size()];
        int i = 0;
        for (PcapNetworkInterface p:nifs) {
            nifList[i] = p.getName();
            i++;
        }

        JList<String> list = new JList<>(nifList);
        DefaultListCellRenderer renderer = (DefaultListCellRenderer) list.getCellRenderer();
        JButton closeScan = new JButton("Close scan!");
        closeScan.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent actionEvent) {
                RUN = false;
            }
        });

        final List<PcapNetworkInterface> interfaces = nifs;
        frame.setSize(400,400);

        frame.setLayout(new BorderLayout());

        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);

        JButton button = new JButton("Start Scan");
        button.setSize(20,30);
        button.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent actionEvent) {
               new Thread(new Runnable() {
                   @Override
                   public void run() {

                       try {
                           nif = findInterface(list.getSelectedValue().toString(), interfaces);
                       }catch (NullPointerException e) {
                               new InterfaceSelectionDialog(frame);
                               return;

                       }
                       RUN = true;
                       int snaplen = 128000;

                       PromiscuousMode mode = PromiscuousMode.PROMISCUOUS;
                       int timeout = 10;
                       PcapHandle handle = null;
                       try {
                           assert nif != null;
                           handle = nif.openLive(snaplen, mode, timeout);
                       } catch (PcapNativeException e) {
                           e.printStackTrace();
                       }
//                } catch (NotOpenException e) {
//                    e.printStackTrace();
//                }
                       StringBuilder attackLogger = new StringBuilder();
                       JFrame packets = new JFrame("ALERTS");
                       packets.setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE);
                       packets.addWindowListener(new WindowListener() {
                           @Override
                           public void windowOpened(WindowEvent windowEvent) {

                           }

                           @Override
                           public void windowClosing(WindowEvent windowEvent) {
                               JDialog dialog = new JDialog();
                               dialog.setSize(500,300);
                               dialog.add(new JLabel("Do you want to save the alerts?"));
                               JButton yesButton = new JButton("YES");
                               yesButton.setSize(500, 20);
                               yesButton.addActionListener(new ActionListener() {
                                   @Override
                                   public void actionPerformed(ActionEvent actionEvent) {
                                       JFileChooser fileChooser = new JFileChooser();
                                       int response = fileChooser.showSaveDialog(null);
                                       if(response == JFileChooser.APPROVE_OPTION){
                                           try{
                                               FileWriter pw = new FileWriter(fileChooser.getSelectedFile());
                                               pw.write(attackLogger.toString());
                                               pw.close();
                                           }catch (Exception e){
                                               e.printStackTrace();
                                           }
                                           dialog.setVisible(false);
                                       }
                                   }
                               });
                               JButton noButton = new JButton("NO");
                               noButton.setSize(500,20);
                               noButton.addActionListener(new ActionListener() {
                                   @Override
                                   public void actionPerformed(ActionEvent actionEvent) {
                                       dialog.setVisible(false);
                                   }
                               });
                               dialog.setLayout(new BorderLayout());
                               dialog.add(new JLabel("Do you want to save the alerts?"),BorderLayout.NORTH);
                               dialog.add(yesButton,BorderLayout.CENTER);
                               dialog.add(noButton,BorderLayout.SOUTH);
                               dialog.pack();
                               dialog.setLocationRelativeTo(null);
                               dialog.setVisible(true);
                           }

                           @Override
                           public void windowClosed(WindowEvent windowEvent) {
                                RUN = false;

                           }

                           @Override
                           public void windowIconified(WindowEvent windowEvent) {

                           }

                           @Override
                           public void windowDeiconified(WindowEvent windowEvent) {

                           }

                           @Override
                           public void windowActivated(WindowEvent windowEvent) {

                           }

                           @Override
                           public void windowDeactivated(WindowEvent windowEvent) {

                           }
                       });
                       packets.setSize(new Dimension(400,400));
                       JList attackList = new JList();
                       List<String> attackArray = new ArrayList<>();

                       PacketListener listener = new PacketListener() {

                           int packetNumber = 0;
                           long startTime = 0;
                           long finishTime = 0;
                           SynFloodAnalyzer analyzer;
                           boolean isDDoS = false;


                           @Override
                           public void gotPacket(PcapPacket pcapPacket) {

                               if(!RUN)
                                   return;
                               packetNumber++;
                               if (packetNumber == 1){
                                   startTime = System.currentTimeMillis();
                                   synFloodMap = new HashMap<>();
                               }

                               if(packetNumber == maxPackets){
                                   finishTime = System.currentTimeMillis();
                                   packetNumber = 0;
                               }

                               IpV6Packet.IpV6Header ipV6Header = null;
                               IpV4Packet.IpV4Header ipV4Header = null;
                               TcpPacket.TcpHeader tcpHeader = null;
                               UdpPacket.UdpHeader udpHeader = null;
                               InetAddress destAddress = null;
                               InetAddress srcAddress = null;
                               IpV6Packet ipV6Packet = pcapPacket.get(IpV6Packet.class);
                               IpV4Packet ipV4Packet = pcapPacket.get(IpV4Packet.class);
                               TcpPacket tcpPacket = pcapPacket.get(TcpPacket.class);
                               UdpPacket udpPacket = pcapPacket.get(UdpPacket.class);

                               boolean isNull = true;

                               if(ipV4Packet!=null){
                                   ipV4Header = ipV4Packet.getHeader();
                                   destAddress = ipV4Header.getDstAddr();
                                   srcAddress = ipV4Header.getSrcAddr();
                                   System.out.println(ipV4Header);
                                   isNull = false;
                               }

                               if(ipV6Packet != null){
                                   ipV6Header = ipV6Packet.getHeader();
                                   destAddress = ipV6Header.getDstAddr();
                                   srcAddress = ipV6Header.getSrcAddr();
                                   System.out.println(ipV6Header);
                                   isNull = false;
                               }

                               if(tcpPacket != null){
                                   tcpHeader = tcpPacket.getHeader();
                                   if(tcpHeader.getSyn() && !tcpHeader.getAck() && !tcpHeader.getFin() && !tcpHeader.getRst() && !tcpHeader.getUrg() && !tcpHeader.getPsh())
                                       if(srcAddress!=null && destAddress != null) {
                                           synFloodMap.put(packetNumber + "-" + srcAddress.toString(), destAddress);
                                       }
                                   System.out.println(tcpHeader);
                                   isNull = false;
                               }

                               if(udpPacket != null){
                                   udpHeader = udpPacket.getHeader();
                                   System.out.println(udpHeader);
                                   isNull = false;
                               }

                               //if(isNull)System.out.println("No packet data could be captured");

                               addAddresses(srcAddress,destAddress);
                               if(destAddress != null && srcAddress != null ) {
                                   String miningPool = miningPoolAnalyzer.isMining(destAddress.toString().substring(1));
                                   if (miningPool != null) {
                                       String alertString = "ALERT! machine corresponding to the address " + srcAddress.toString().substring(1) + " has accessed crypto mining website: " + miningPool + " at " + DateTimeFormatter.ofPattern("yyyy/MM/dd HH:mm:ss").format(LocalDateTime.now());
                                       attackLogger.append(alertString).append("\n");
                                       attackArray.add(alertString);
                                       attackList.setListData(attackArray.toArray());
                                       System.out.println(alertString);
                                   }
                               }
                               if(startTime != 0 && finishTime != 0){
                                   long executionTime = finishTime - startTime;
                                   //System.out.println("it took " + executionTime + " milliseconds to execute");
                                   analyzer = new SynFloodAnalyzer(synFloodMap,executionTime,maxPackets);
                                   boolean analyzeResult = analyzer.isDoSAttack();
                                   if(analyzeResult){
                                       String ddosString = "ALERT! DDoS ATTACK STARTED AT " + analyzer.getTime() + " WITH " + analyzer.getVictim() + " AS VICTIM";
                                       attackLogger.append(ddosString).append("\n");
                                       attackArray.add(ddosString);
                                       attackList.setListData(attackArray.toArray());
                                       System.out.println(ddosString);
                                       isDDoS = true;
                                   }else{
                                       isDDoS=false;
                                   }
                                   startTime = 0;
                                   finishTime = 0;
                               }
                           }
                       };

                       String[] attacks = new String[attackArray.size()];
                       Iterator<String> iterator = attackArray.iterator();
                       int i = 0;
                       while(iterator.hasNext()){
                           attacks[i] = iterator.next();
                           i++;
                       }
                       if(attacks.length == 0){
                           attacks = new String[1];
                           attacks[0] = "No alert were found";
                       }
                       attackList.setListData(attacks);
                       JScrollPane sp = new JScrollPane(attackList);
                       packets.add(sp);
                       packets.setSize(400,400);
                       packets.setLocationRelativeTo(frame);
                       packets.setVisible(true);

                       try{
                           long startTime = System.currentTimeMillis();
                           while(RUN){
                               handle.loop(maxPackets, listener);
                           }
                       }catch (InterruptedException | PcapNativeException | NotOpenException e){
                           e.printStackTrace();
                       }

                       System.out.println(" The source addresses were the following");
                       for(InetAddress s: accessMap.keySet()){
                           System.out.println(s.toString().substring(1));
                           for(InetAddress d:accessMap.get(s)){
                               System.out.println("\t"+"|-" + d.toString().substring(1));
                           }
                       }


                       handle.close();
                   }
               }).start();
            }
        });

//        JPanel northPanel = new JPanel();
//        northPanel.setLayout(new BoxLayout(northPanel,BoxLayout.LINE_AXIS));
//        northPanel.add(new JLabel("Interfaces"));
//        northPanel.add(list);
        panel.setLayout(new BorderLayout());
        panel.add(list,BorderLayout.NORTH);
        panel.add(closeScan,BorderLayout.EAST);
        panel.add(button,BorderLayout.CENTER);
        //panel.add(sp,BorderLayout.SOUTH);
        frame.setContentPane(panel);
        frame.setLocationRelativeTo(null);
        frame.setVisible(true);

    }


    public static void addAddresses(InetAddress srcAddress, InetAddress destAddress){
        if(srcAddress != null && destAddress != null) {
            if (!accessMap.containsKey(srcAddress)) {
                accessMap.put(srcAddress, Collections.synchronizedList(new ArrayList<>()));
                accessMap.get(srcAddress).add(destAddress);
            } else {
                for (InetAddress a : accessMap.keySet()) {
                    if (a.equals(srcAddress))
                        accessMap.get(a).add(destAddress);
                }
            }
        }
    }

    public static PcapNetworkInterface findInterface(String nifName, List<PcapNetworkInterface> nifs){
        Iterator<PcapNetworkInterface> iterator = nifs.iterator();
        PcapNetworkInterface nif;
        while(iterator.hasNext()){
            nif = iterator.next();
            if(nif.getName().equals(nifName)){
                return nif;
            }
        }

        return null;
    }

    public static String[] showAlerts(List<String> alertList, String alert){

        return null;
    }
}
