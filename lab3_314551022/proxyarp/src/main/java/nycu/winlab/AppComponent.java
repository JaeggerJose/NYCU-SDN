/*
 * Copyright 2024-present Open Networking Foundation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package nycu.winlab.proxyarp;

import org.onosproject.cfg.ComponentConfigService;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.ByteBuffer;
import java.util.Map;
import java.util.HashMap;

import org.onosproject.core.ApplicationId;
import org.onosproject.core.CoreService;

import org.onosproject.net.flow.DefaultTrafficSelector;
import org.onosproject.net.flow.TrafficSelector;

import org.onosproject.net.packet.PacketPriority;
import org.onosproject.net.packet.PacketService;
import org.onosproject.net.packet.PacketProcessor;
import org.onosproject.net.packet.PacketContext;
import org.onosproject.net.packet.InboundPacket;
import org.onosproject.net.packet.OutboundPacket;
import org.onosproject.net.packet.DefaultOutboundPacket;

import org.onlab.packet.Ethernet;
import org.onlab.packet.MacAddress;
import org.onlab.packet.ARP;
import org.onlab.packet.Ip4Address;

import org.onosproject.net.ConnectPoint;
import org.onosproject.net.edge.EdgePortService;
import org.onosproject.net.flow.DefaultTrafficTreatment;
import org.onosproject.net.flow.TrafficTreatment;


/**
 * Proxy ARP Application.
 */
@Component(immediate = true)
public class AppComponent {

    private final Logger log = LoggerFactory.getLogger(getClass());

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected ComponentConfigService cfgService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected CoreService coreService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected PacketService packetService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected EdgePortService edgePortService;

    private ProxyArpProcessor processor = new ProxyArpProcessor();
    private ApplicationId appId;

    // ARP table: IP -> MAC mapping
    private Map<Ip4Address, MacAddress> arpTable = new HashMap<>();

    @Activate
    protected void activate() {
        // Register app
        appId = coreService.registerApplication("nycu.winlab.proxyarp");

        // Add packet processor
        packetService.addProcessor(processor, PacketProcessor.director(3));

        // Request ARP packets
        TrafficSelector.Builder selector = DefaultTrafficSelector.builder();
        selector.matchEthType(Ethernet.TYPE_ARP);
        packetService.requestPackets(selector.build(), PacketPriority.REACTIVE, appId);

        log.info("Started");
    }

    @Deactivate
    protected void deactivate() {
        // Remove packet processor
        packetService.removeProcessor(processor);
        processor = null;

        // Cancel packet requests
        TrafficSelector.Builder selector = DefaultTrafficSelector.builder();
        selector.matchEthType(Ethernet.TYPE_ARP);
        packetService.cancelPackets(selector.build(), PacketPriority.REACTIVE, appId);

        log.info("Stopped");
    }

    private class ProxyArpProcessor implements PacketProcessor {

        @Override
        public void process(PacketContext context) {
            // Stop processing if already handled
            if (context.isHandled()) {
                return;
            }

            InboundPacket pkt = context.inPacket();
            Ethernet ethPkt = pkt.parsed();

            if (ethPkt == null) {
                return;
            }

            // Check if it's ARP packet
            if (ethPkt.getEtherType() != Ethernet.TYPE_ARP) {
                return;
            }

            ARP arpPkt = (ARP) ethPkt.getPayload();
            Ip4Address srcIp = Ip4Address.valueOf(arpPkt.getSenderProtocolAddress());
            Ip4Address dstIp = Ip4Address.valueOf(arpPkt.getTargetProtocolAddress());
            MacAddress srcMac = MacAddress.valueOf(arpPkt.getSenderHardwareAddress());

            // Learn sender's IP-MAC mapping
            arpTable.put(srcIp, srcMac);

            // Handle ARP Request
            if (arpPkt.getOpCode() == ARP.OP_REQUEST) {
                handleArpRequest(context, ethPkt, arpPkt, srcIp, srcMac, dstIp);
            } else if (arpPkt.getOpCode() == ARP.OP_REPLY) {
                // Handle ARP Reply
                handleArpReply(context, ethPkt, arpPkt, srcIp, srcMac);
            }
        }

        private void handleArpRequest(PacketContext context, Ethernet ethPkt, ARP arpPkt,
                                     Ip4Address srcIp, MacAddress srcMac, Ip4Address dstIp) {
            // Check if we have the target MAC in ARP table
            MacAddress dstMac = arpTable.get(dstIp);

            if (dstMac != null) {
                // TABLE HIT - Send ARP Reply
                log.info("TABLE HIT. Requested MAC = " + dstMac.toString());
                sendArpReply(context, ethPkt, arpPkt, dstMac);
            } else {
                // TABLE MISS - Flood to edge ports
                log.info("TABLE MISS. Send request to edge ports");
                floodArpRequest(context, ethPkt);
            }
        }

        private void handleArpReply(PacketContext context, Ethernet ethPkt, ARP arpPkt,
                                   Ip4Address srcIp, MacAddress srcMac) {
            log.info("RECV REPLY. Requested MAC = " + srcMac.toString());
            // ARP reply is already learned in the beginning
            // Just let it through (don't block)
        }

        private void sendArpReply(PacketContext context, Ethernet ethPkt, ARP arpPkt, MacAddress dstMac) {
            // Build ARP Reply
            ARP arpReply = new ARP();
            arpReply.setHardwareType(ARP.HW_TYPE_ETHERNET);
            arpReply.setProtocolType(ARP.PROTO_TYPE_IP);
            arpReply.setHardwareAddressLength((byte) Ethernet.DATALAYER_ADDRESS_LENGTH);
            arpReply.setProtocolAddressLength((byte) Ip4Address.BYTE_LENGTH);
            arpReply.setOpCode(ARP.OP_REPLY);
            arpReply.setSenderHardwareAddress(dstMac.toBytes());
            arpReply.setSenderProtocolAddress(arpPkt.getTargetProtocolAddress());
            arpReply.setTargetHardwareAddress(arpPkt.getSenderHardwareAddress());
            arpReply.setTargetProtocolAddress(arpPkt.getSenderProtocolAddress());

            // Build Ethernet frame
            Ethernet ethReply = new Ethernet();
            ethReply.setEtherType(Ethernet.TYPE_ARP);
            ethReply.setSourceMACAddress(dstMac);
            ethReply.setDestinationMACAddress(ethPkt.getSourceMAC());
            ethReply.setPayload(arpReply);

            // Send packet out through the incoming port
            TrafficTreatment treatment = DefaultTrafficTreatment.builder()
                    .setOutput(context.inPacket().receivedFrom().port())
                    .build();

            OutboundPacket packet = new DefaultOutboundPacket(
                    context.inPacket().receivedFrom().deviceId(),
                    treatment,
                    ByteBuffer.wrap(ethReply.serialize()));

            packetService.emit(packet);
            context.block();
        }

        private void floodArpRequest(PacketContext context, Ethernet ethPkt) {
            ConnectPoint ingressPoint = context.inPacket().receivedFrom();
            // Flood to ALL edge ports (on all switches), except incoming port
            for (ConnectPoint cp : edgePortService.getEdgePoints()) {
                // Skip the incoming port
                if (cp.equals(ingressPoint)) {
                    continue;
                }
                TrafficTreatment treatment = DefaultTrafficTreatment.builder()
                        .setOutput(cp.port())
                        .build();
                OutboundPacket packet = new DefaultOutboundPacket(
                        cp.deviceId(),
                        treatment,
                        ByteBuffer.wrap(ethPkt.serialize()));
                packetService.emit(packet);
            }
            context.block();
        }
    }
}