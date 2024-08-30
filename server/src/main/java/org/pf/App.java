package org.pf;

import com.sun.jna.Platform;
import org.pcap4j.core.*;
import org.pcap4j.packet.IcmpV4CommonPacket;
import org.pcap4j.packet.IcmpV4EchoPacket;
import org.pcap4j.packet.IpPacket;
import org.pcap4j.packet.Packet;
import org.pcap4j.util.ByteArrays;
import org.pcap4j.util.NifSelector;

import java.io.IOException;

/**
 * Hello world!
 *
 */
public class App 
{

    private static final String COUNT_KEY = App.class.getName() + ".count";
    private static final int COUNT = Integer.getInteger(COUNT_KEY, 5);

    private static final String READ_TIMEOUT_KEY = App.class.getName() + ".readTimeout";
    private static final int READ_TIMEOUT = Integer.getInteger(READ_TIMEOUT_KEY, 10);

    private static final String SNAPLEN_KEY = App.class.getName() + ".snaplen";
    private static final int SNAPLEN = Integer.getInteger(SNAPLEN_KEY, 65536);


    private static final String NIF_NAME = "ens33";

    public static void main( String[] args ) throws Exception {
        String filter = args.length != 0 ? args[0] : "";

        PcapNetworkInterface nif;
        if (NIF_NAME != null) {
            nif = Pcaps.getDevByName(NIF_NAME);
        } else {
            try {
                nif = new NifSelector().selectNetworkInterface();
            } catch (IOException e) {
                e.printStackTrace();
                return;
            }

            if (nif == null) {
                return;
            }
        }


        System.out.println(nif.getName() + " (" + nif.getDescription() + ")");
        for (PcapAddress addr : nif.getAddresses()) {
            if (addr.getAddress() != null) {
                System.out.println("IP address: " + addr.getAddress());
            }
        }
        System.out.println("");

        PcapHandle handle = nif.openLive(SNAPLEN, PcapNetworkInterface.PromiscuousMode.PROMISCUOUS, READ_TIMEOUT);

        handle.setFilter(filter, BpfProgram.BpfCompileMode.OPTIMIZE);

        int num = 0;
        while (true) {
            Packet packet = handle.getNextPacket();
            if (packet == null) {
                continue;
            } else {
                String src = null;
                IpPacket ipPacket =  packet.get(IpPacket.class);
                if (ipPacket != null) {
                     src = ipPacket.getHeader().getSrcAddr().getHostAddress();
                }



                if (packet.contains(IcmpV4EchoPacket.class)){
                    IcmpV4EchoPacket echoPacket = packet.get(IcmpV4EchoPacket.class);
                    String identifier = new String(echoPacket.getPayload().getRawData());
                    System.out.println(src);
                    System.out.println(identifier);
                }


               // num++;
//                if (num >= COUNT) {
//                    break;
//                }
            }

        }

//        PcapStat ps = handle.getStats();
//        System.out.println("ps_recv: " + ps.getNumPacketsReceived());
//        System.out.println("ps_drop: " + ps.getNumPacketsDropped());
//        System.out.println("ps_ifdrop: " + ps.getNumPacketsDroppedByIf());
//        if (Platform.isWindows()) {
//            System.out.println("bs_capt: " + ps.getNumPacketsCaptured());
//        }
//
//        handle.close();


    }
}
