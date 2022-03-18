package com.main;

import com.analyze.SynFloodAnalyzer;
import org.pcap4j.core.*;
import org.pcap4j.core.PcapNetworkInterface.*;
import org.pcap4j.packet.*;
import org.pcap4j.util.NifSelector;

import java.io.*;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.*;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeoutException;
import java.util.logging.Level;
import java.util.logging.Logger;

public class MainApp {

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
    //main method for capturing the packets
    public static void main(String[] args) throws UnknownHostException, PcapNativeException, NotOpenException, EOFException, TimeoutException {
        Logger.getLogger("ac.biu.nlp.nlp.engineml").setLevel(Level.OFF);
        Logger.getLogger("org.BIU.utils.logging.ExperimentLogger").setLevel(Level.OFF);
       // Logger.getRootLogger().setLevel(Level.OFF);

        PcapNetworkInterface nif = getInterface();
        System.out.println("You chose " + nif.getName());
        System.out.println(nif.getName());

        int snaplen = 1280000;

        PromiscuousMode mode = PcapNetworkInterface.PromiscuousMode.PROMISCUOUS;
        int timeout = 10;
        PcapHandle handle = nif.openLive(snaplen, mode, timeout);
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

                    if(packetNumber == 200){
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
                        //System.out.println(ipV4Header);
                        isNull = false;
                    }

                    if(ipV6Packet != null){
                        ipV6Header = ipV6Packet.getHeader();
                        destAddress = ipV6Header.getDstAddr();
                        srcAddress = ipV6Header.getSrcAddr();
                       // System.out.println(ipV6Header);
                        isNull = false;
                    }

                    if(tcpPacket != null){
                        tcpHeader = tcpPacket.getHeader();
                        if(tcpHeader.getSyn() && !tcpHeader.getAck() && !tcpHeader.getFin() && !tcpHeader.getRst() && !tcpHeader.getUrg() && !tcpHeader.getPsh())
                            if(srcAddress!=null && destAddress != null) {
                                synFloodMap.put(packetNumber + "-" + srcAddress.toString(), destAddress);
                            }
                        //System.out.println(tcpHeader);
                        isNull = false;
                    }

                    if(udpPacket != null){
                        udpHeader = udpPacket.getHeader();
                      //  System.out.println(udpHeader);
                        isNull = false;
                    }

                    //if(isNull)System.out.println("No packet data could be captured");

                   addAddresses(srcAddress,destAddress);

                   if(startTime != 0 && finishTime != 0){
                       long executionTime = finishTime - startTime;
                       //System.out.println("it took " + executionTime + " milliseconds to execute");
                       analyzer = new SynFloodAnalyzer(synFloodMap,executionTime);
                       boolean analyzeResult = analyzer.isDoSAttack();
                       if(analyzeResult){
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
            int maxPackets = 200;
            handle.loop(maxPackets, listener);
            }
        }catch (InterruptedException e){
            e.printStackTrace();
        }

//        System.out.println(" The source addresses were the following");
//        for(InetAddress s: accessMap.keySet()){
//            System.out.println(s.toString().substring(1));
//            for(InetAddress d:accessMap.get(s)){
//                System.out.println("\t"+"|-" + d.toString().substring(1));
//            }
//        }

        handle.close();

    }

    public static String scanIP(InetAddress address){
        String output;
        Process p;
        StringBuilder result = new StringBuilder();
        try{
            String command = "nmap -A -T4 " + address.toString().substring(1);
            p = Runtime.getRuntime().exec(command);
            System.out.println("The command " + command + " was executed");
            BufferedReader br = new BufferedReader(new InputStreamReader(p.getInputStream()));
            while((output = br.readLine()) != null){
                result.append(output).append("\n");
            }
            p.waitFor();
            p.destroy();
        }catch (Exception e){
            e.printStackTrace();
        }

        return result.toString();
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
}
