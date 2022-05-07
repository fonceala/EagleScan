package com.main;

import com.analyze.MiningPoolAnalyzer;
import com.analyze.SynFloodAnalyzer;
import org.pcap4j.core.*;
import org.pcap4j.core.PcapNetworkInterface.*;
import org.pcap4j.packet.*;
import org.pcap4j.util.NifSelector;

import javax.swing.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.*;
import java.net.InetAddress;
import java.net.URISyntaxException;
import java.net.UnknownHostException;
import java.util.*;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeoutException;
import java.util.logging.Level;
import java.util.logging.Logger;

public class MainApp extends JFrame {


    static PcapNetworkInterface getInterface(){
        PcapNetworkInterface device = null;
        try{
            device = new NifSelector().selectNetworkInterface();
        }catch (IOException e){
            e.printStackTrace();
        }

        return device;
    }

    private static final Map<InetAddress,List<InetAddress>> accessMap = new HashMap<>();
    private static Map<String,InetAddress> synFloodMap = new HashMap<>();
    private static final MiningPoolAnalyzer miningPoolAnalyzer = new MiningPoolAnalyzer();

    final static int maxPackets = 1500;
    //main method for capturing the packets
    public static void main(String[] args) throws UnknownHostException, PcapNativeException, NotOpenException, EOFException, TimeoutException {
        JFrame frame = new JFrame("Eagle Scan");
        JPanel panel = new JPanel();

        List<PcapNetworkInterface> nifs = Pcaps.findAllDevs();
        String[] nifList = new String[nifs.size()];
        int i = 0;
        for (PcapNetworkInterface p:nifs) {
            nifList[i] = p.getName();
            i++;
        }

        JList list = new JList(nifList);
        panel.add(list);

        frame.setSize(1000,1000);

        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);

        JTextArea ta = new JTextArea(400,500);
        ta.setEditable(false);
        JScrollPane sp = new JScrollPane(ta);
        JButton button = new JButton("Select NIF");

        button.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent actionEvent) {
                PcapNetworkInterface nif = findInterface(list.getSelectedValue().toString(),nifs);

                int snaplen = 12800000;

                PromiscuousMode mode = PcapNetworkInterface.PromiscuousMode.PROMISCUOUS;
                int timeout = 10;
                PcapHandle handle = null;
                try {
                    assert nif != null;
                    handle = nif.openLive(snaplen, mode, timeout);
                } catch (PcapNativeException e) {
                    e.printStackTrace();
                }
                PacketListener listener = new PacketListener() {

                    int packetNumber = 0;
                    long startTime = 0;
                    long finishTime = 0;
                    SynFloodAnalyzer analyzer;
                    boolean isDDoS = false;


                    @Override
                    public void gotPacket(PcapPacket pcapPacket) {

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
                            ta.append(ipV4Header.toString()+"\n");
                            System.out.println(ipV4Header);
                            isNull = false;
                        }

                        if(ipV6Packet != null){
                            ipV6Header = ipV6Packet.getHeader();
                            destAddress = ipV6Header.getDstAddr();
                            srcAddress = ipV6Header.getSrcAddr();
                            ta.append(ipV6Header.toString()+"\n");
                            System.out.println(ipV6Header);
                            isNull = false;
                        }

                        if(tcpPacket != null){
                            tcpHeader = tcpPacket.getHeader();
                            if(tcpHeader.getSyn() && !tcpHeader.getAck() && !tcpHeader.getFin() && !tcpHeader.getRst() && !tcpHeader.getUrg() && !tcpHeader.getPsh())
                                if(srcAddress!=null && destAddress != null) {
                                    synFloodMap.put(packetNumber + "-" + srcAddress.toString(), destAddress);
                                }
                            ta.append(tcpHeader.toString());
                            //System.out.println(tcpHeader);
                            isNull = false;
                        }

                        if(udpPacket != null){
                            udpHeader = udpPacket.getHeader();
                            ta.append(udpHeader.toString());
                            //  System.out.println(udpHeader);
                            isNull = false;
                        }

                        //if(isNull)System.out.println("No packet data could be captured");

                        addAddresses(srcAddress,destAddress);
                        if(destAddress != null && srcAddress != null ) {
                            String miningPool = miningPoolAnalyzer.isMining(destAddress.toString().substring(1));
                            if (miningPool != null) {
                                ta.append("ALERT! machine corresponding to the address " + srcAddress.toString().substring(1) + " has accessed crypto mining website: " + miningPool+"\n");
                                System.out.println("ALERT! machine corresponding to the address " + srcAddress.toString().substring(1) + " has accessed crypto mining website: " + miningPool);
                            }
                        }
                        if(startTime != 0 && finishTime != 0){
                            long executionTime = finishTime - startTime;
                            //System.out.println("it took " + executionTime + " milliseconds to execute");
                            analyzer = new SynFloodAnalyzer(synFloodMap,executionTime,maxPackets);
                            boolean analyzeResult = analyzer.isDoSAttack();
                            if(analyzeResult){
                                ta.append("ALERT! DDoS ATTACK STARTED AT " + analyzer.getTime() + " WITH " + analyzer.getVictim() + " AS VICTIM" + "\n");
                                System.out.println("ALERT! DDoS ATTACK STARTED AT " + analyzer.getTime() + " WITH " + analyzer.getVictim() + " AS VICTIM");
                                isDDoS = true;
                            }else{
                                isDDoS=false;
                            }
                            startTime = 0;
                            finishTime = 0;
                        }
                    }
                };

                try{
                    long startTime = System.currentTimeMillis();
                    while((System.currentTimeMillis() - startTime) < 360000){

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
        });


        panel.add(button);
        panel.add(sp);
        frame.add(panel);
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
}
