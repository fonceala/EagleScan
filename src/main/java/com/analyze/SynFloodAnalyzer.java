package com.analyze;

import java.net.InetAddress;
import java.util.HashMap;
import java.util.Map;

public class SynFloodAnalyzer {

    private Map<String,InetAddress> synFloodMap;
    private Map<InetAddress,Integer> numOfAppearances;

    private int duration;
    private final int PERCENTAGE = 80;

    public SynFloodAnalyzer(Map<String,InetAddress> synFloodMap, int duration){
        this.synFloodMap = synFloodMap;
        numOfAppearances = new HashMap<>();
        this.duration = duration;
    }

    public boolean isDoSAttack(){
        boolean isFlood = false;

        for(String srcAddr: synFloodMap.keySet()){
            InetAddress dstAddr = synFloodMap.get(srcAddr);
            boolean exists = false;
            for(InetAddress addr: numOfAppearances.keySet()){
                if(addr.toString().equals(dstAddr.toString())){

                }
            }
        }

        return isFlood;
    }
}
