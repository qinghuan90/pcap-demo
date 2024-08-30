package org.pf.utils;/**
 * @fileName NetworkInterfaceUtil
 * @author pengfei
 * @date 2024/8/30
 * @description NetworkInterfaceUtil
 */

import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.Pcaps;

import java.util.ArrayList;
import java.util.List;

/**
 * @author pengfei
 * @date 2024/8/30
 * @description NetworkInterfaceUtil
 */
public class NetworkInterfaceUtil {


    public static List<PcapNetworkInterface> findAllInterfaces(){
        List<PcapNetworkInterface> interfaces = new ArrayList<>();
        try {
            interfaces = Pcaps.findAllDevs();
            for (PcapNetworkInterface nif : interfaces) {
                System.out.println(nif.getName() + " : " + nif.getDescription());
            }
        } catch (Exception e) {
            e.printStackTrace();
        }

        return interfaces;
    }
}
