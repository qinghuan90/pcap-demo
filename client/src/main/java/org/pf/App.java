package org.pf;

import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.Pcaps;
import org.pcap4j.packet.*;
import org.pcap4j.packet.namednumber.*;
import org.pcap4j.util.MacAddress;
import org.pcap4j.util.NifSelector;

import java.net.Inet4Address;
import java.net.InetAddress;
import java.util.List;

/**
 * Hello world!
 *
 */
public class App 
{
    public static void main( String[] args ) throws Exception {

        PcapNetworkInterface nif = Pcaps.getDevByName("ens33");
        PcapHandle sendHandle = nif.openLive(65536, PcapNetworkInterface.PromiscuousMode.PROMISCUOUS, 60);

        String identifier = "flag:pf";
        System.out.println(identifier);

        byte[] echoData = identifier.getBytes();
        IcmpV4EchoPacket.Builder echoBuilder = new IcmpV4EchoPacket.Builder();
        echoBuilder
                .identifier((short) 1)
                .payloadBuilder(new UnknownPacket.Builder().rawData(echoData));

        IcmpV4CommonPacket.Builder icmpV4CommonBuilder = new IcmpV4CommonPacket.Builder();
        icmpV4CommonBuilder
                .type(IcmpV4Type.ECHO)
                .code(IcmpV4Code.NO_CODE)
                .payloadBuilder(echoBuilder)
                .correctChecksumAtBuild(true);



        // 构建自定义 IPv4 包
        IpV4Packet.Builder ipV4Builder = new IpV4Packet.Builder()
                .version(IpVersion.IPV4)
                .tos(IpV4Rfc791Tos.newInstance((byte) 0))
                .ttl((byte) 100)
                .protocol(IpNumber.ICMPV4)
                .srcAddr((Inet4Address) InetAddress.getByName("192.168.1.01"))
                .dstAddr((Inet4Address) InetAddress.getByName("192.168.18.128"))
                .payloadBuilder(icmpV4CommonBuilder)
                .correctChecksumAtBuild(true)
                .correctLengthAtBuild(true);

        // 构建以太网包
        EthernetPacket.Builder etherBuilder = new EthernetPacket.Builder()
                .dstAddr(MacAddress.getByName("ff:ff:ff:ff:ff:ff"))
                .srcAddr(MacAddress.getByName("00:11:22:33:44:55"))
                .type(EtherType.IPV4)
                .payloadBuilder(ipV4Builder)
                .paddingAtBuild(true);

        Packet p = etherBuilder.build();
        sendHandle.sendPacket(p);


        sendHandle.close();
    }
}
