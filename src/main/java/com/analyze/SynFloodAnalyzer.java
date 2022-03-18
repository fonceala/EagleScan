package com.analyze;

import java.net.InetAddress;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.HashMap;
import java.util.Map;

public class SynFloodAnalyzer {

    private Map<String,InetAddress> synFloodMap;
    private Map<InetAddress,Integer> numOfAppearances;

    private long duration;
    private final long EXPECTED_DURATION = 200;
    private final int PERCENTAGE = 70;
    private InetAddress victim;
    private LocalDateTime now;

    public SynFloodAnalyzer(Map<String,InetAddress> synFloodMap, long duration){
        this.synFloodMap = synFloodMap;
        numOfAppearances = new HashMap<>();
        this.duration = duration;
    }

    public boolean isDoSAttack(){

        boolean isDDoS = false;

        for(String srcAddr: synFloodMap.keySet()){

            InetAddress dstAddr = synFloodMap.get(srcAddr);

            boolean exists = false;
            for(InetAddress addr: numOfAppearances.keySet()){
                if(addr.toString().equals(dstAddr.toString())){
                    exists = true;
                }
            }
            if(!exists){
                numOfAppearances.put(dstAddr,1);
            }else{
                numOfAppearances.replace(dstAddr,numOfAppearances.get(dstAddr)+1);
            }

        }

        int percentage_appearances = 90;
        Integer max_appearances = 0;
        for(InetAddress addr: numOfAppearances.keySet()){
            if(numOfAppearances.get(addr) >= max_appearances){
                max_appearances = numOfAppearances.get(addr);
                victim = addr;
            }
        }
        now = LocalDateTime.now();

        if((max_appearances/synFloodMap.size()) * 100 >= percentage_appearances && !((synFloodMap.size() / 200 * 100) < PERCENTAGE || duration >= EXPECTED_DURATION)){
            isDDoS = true;
        }

        return isDDoS;
    }

    public InetAddress getVictim(){
        return victim;
    }

    public String getTime(){
        DateTimeFormatter dtf = DateTimeFormatter.ofPattern("yyyy/MM/dd HH:mm:ss");
        return dtf.format(now);
    }
}
