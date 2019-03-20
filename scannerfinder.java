/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package assignment4;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.nio.Buffer;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Hashtable;
import java.util.List;
import java.util.Map;

import org.jnetpcap.*;
import org.jnetpcap.PcapIf;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.PcapPacketHandler;
import org.jnetpcap.packet.annotate.Protocol;
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.tcpip.Tcp;
/**
 *
 * @author Conner McCloney and Amanda Hawkins
 */
public class scannerfinder {

    /**
     * @param args the command line arguments
     */
    @SuppressWarnings("deprecation")
    public static void main(String[] args) throws IOException {
        String filename = "";
        // TODO code application logic here
        
        if(args.length == 0){
            System.out.println("Please enter an argument");
        }else{
            filename = args[0];
            for(int i = 1; i < args.length; i++){
                filename = filename + " " + args[i];
            }
        }
        
	StringBuilder errbuf = new StringBuilder(); // For any error msgs
        int snaplen = 64 * 1024; // Capture all packets, no trucation
	int flags = Pcap.MODE_PROMISCUOUS; // capture all packets
	int timeout = 10 * 1000; // 10 seconds in millis
	Pcap pcap = Pcap.openOffline(filename, errbuf);
	if (pcap == null) {
		System.err.printf("Error while opening device for capture: "
				+ errbuf.toString());
		return;
	}
        //keeps track of the number of
        //source and dest. IPs sent and received in packets analyzed
        Map<String, Object> sources = new HashMap<>();
        Map<String, Object> destinations = new HashMap<>();
        
	PcapPacketHandler<String> jpacketHandler = new PcapPacketHandler<String>() {
            public void nextPacket(PcapPacket packet, String user) {
                byte[] data = packet.getByteArray(0, packet.size()); // the package data
                byte[] sIP = new byte[4];
                byte[] dIP = new byte[4];
                String sourceIP = "";
                String destIP = "";
                Ip4 ip = new Ip4();
                Tcp tcp = new Tcp();
                
                if(packet.hasHeader(ip) && packet.hasHeader(tcp)){
                    sIP = packet.getHeader(ip).source();
                    sourceIP = org.jnetpcap.packet.format.FormatUtils.ip(sIP);
                    dIP = packet.getHeader(ip).destination();
                    destIP = org.jnetpcap.packet.format.FormatUtils.ip(dIP);

                    //System.out.println("*" + sourceIP + " *" + destIP);
                    //System.out.println("Source IP " + sourceIP);
                    //System.out.println("Destination IP " + destIP);
                
                    
                    
                    if(sources.get(sourceIP) == null){
                        sources.put(sourceIP,1);
                    }else{
                        int temp = (int) sources.get(sourceIP);
                        temp += 1;
                        sources.put(sourceIP,temp);
                    }
                    
                    if(destinations.get(destIP) == null){
                        destinations.put(destIP,1);
                    }else{
                        int temp = (int) destinations.get(destIP);
                        temp += 1;
                        destinations.put(destIP,temp);
                    }
                }
            }
	};
        
        int numloops = 1000000;
        pcap.loop(numloops, jpacketHandler, "jNetPcap");
        //1,000,000 loops takes 5-6 minutes
        //2,000,000 loops takes 12 minutes
        //10,000,000 loops takes 33 minutes
        //
        pcap.close();
        //System.out.println(sources);
        //System.out.println(destinations);
        for(Map.Entry<String,Object> entry : sources.entrySet()){
            String key = entry.getKey();
            int val = (int) entry.getValue();
            if(destinations.get(key) != null){
                int temp = (int) destinations.get(key);
                //System.out.println(val + "vs." + temp);
                if(val >= 3*temp){
                    System.out.println(key);
                }
            }
        }
    }
}
