package com.main;

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

    private static Map<InetAddress,List<InetAddress>> accessMap = new HashMap<>();

    //main method for capturing the packets
    public static void main(String[] args) throws UnknownHostException, PcapNativeException, NotOpenException, EOFException, TimeoutException {
        PcapNetworkInterface nif = getInterface();
        System.out.println("You chose " + nif.getName());
        System.out.println(nif.getName());
        int snaplen = 1280000;
        PromiscuousMode mode = PcapNetworkInterface.PromiscuousMode.PROMISCUOUS;
        int timeout = 10;
        List<InetAddress> sourceList = Collections.synchronizedList(new ArrayList<>());
        List<InetAddress> destList = Collections.synchronizedList(new ArrayList<>());
        PcapHandle handle = nif.openLive(snaplen, mode, timeout);
        PacketListener listener = new PacketListener() {
            @Override
            public void gotPacket(PcapPacket pcapPacket) {

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
                        System.out.println(tcpHeader);
                        isNull = false;
                    }

                    if(udpPacket != null){
                        udpHeader = udpPacket.getHeader();
                        System.out.println(udpHeader);
                        isNull = false;
                    }
                    if(isNull)System.out.println("No packet data could be captured");

                   addAddresses(srcAddress,destAddress);

            }
        };

        try{
            long startTime = System.currentTimeMillis();
            while((System.currentTimeMillis() - startTime) < 3600000*6){
                int maxPackets = 200;
                handle.loop(maxPackets, listener);
            }
        }catch (InterruptedException e){
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
                result.append(output + "\n");
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
