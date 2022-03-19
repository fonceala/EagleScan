package com.analyze;

import java.io.*;
import java.net.InetAddress;
import java.net.URISyntaxException;
import java.net.URL;
import java.util.HashMap;
import java.util.Map;

public class MiningPoolAnalyzer {

    private Map<String,String> miningPoolIP;
    private final String MINING_POOLS = "ips.txt";

    public MiningPoolAnalyzer() throws URISyntaxException, IOException, IllegalAccessException {
        this.miningPoolIP = new HashMap<>();
        parseMap();
    }

    public boolean scanIP(String addr){

    }

    private void parseMap() throws IllegalAccessException, URISyntaxException, IOException {

        ClassLoader classLoader = getClass().getClassLoader();

        File miningAddrs = null;

        URL resource = classLoader.getResource(MINING_POOLS);

        if(resource == null){
            throw new IllegalAccessException("file not found!" + MINING_POOLS);
        }else{
            miningAddrs = new File(resource.toURI());
        }

        BufferedReader reader = new BufferedReader(new FileReader(miningAddrs));
        String line;

        while((line = reader.readLine()) != null){
            String[] values = line.split("=");
            miningPoolIP.put(values[0],values[1]);
        }

    }
}
