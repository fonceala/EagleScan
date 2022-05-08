package com.main;

import java.io.*;
import java.net.InetAddress;
import java.net.URISyntaxException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;

public class MiningPoolAnalyzer {

    private Map<String,String> miningPoolIP;
    private final String MINING_POOLS = "ips.txt";

    public MiningPoolAnalyzer() {
        this.miningPoolIP = new HashMap<>();
        parseMap();
    }

    public String isMining(String addr){
        String miningWebsite = null;
        for(String dst: miningPoolIP.keySet()){
            if(dst.equals(addr)){
                miningWebsite = miningPoolIP.get(dst);
                return miningWebsite;
            }
        }

        return null;
    }

    private void parseMap() {

        ClassLoader classLoader = getClass().getClassLoader();

        File miningAddrs = null;

        URL resource = classLoader.getResource(MINING_POOLS);

        if(resource == null){
            try {
                throw new IllegalAccessException("file not found!" + MINING_POOLS);
            } catch (IllegalAccessException e) {
                e.printStackTrace();
            }
        }else{
            try {
                miningAddrs = new File(resource.toURI());
            } catch (URISyntaxException e) {
                e.printStackTrace();
            }
        }

        BufferedReader reader = null;
        try {
            reader = new BufferedReader(new FileReader(miningAddrs));
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        }
        String line;

        try {
            while ((line = reader.readLine()) != null) {
                String[] values = line.split("=");
                miningPoolIP.put(values[0], values[1]);
            }
        }catch (IOException e){
            e.printStackTrace();
        }

    }
}
