/*
 * Copyright 2025-present Open Networking Foundation
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
package nycu.winlab.unicastdhcp;

import org.onosproject.cfg.ComponentConfigService;
//import org.osgi.service.component.ComponentContext;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
//import org.osgi.service.component.annotations.Modified;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

//import java.util.Dictionary;
//import java.util.Properties;

//import static org.onlab.util.Tools.get;
import org.onosproject.net.ConnectPoint;
import org.onosproject.net.device.DeviceService;
//packet processor
import org.onosproject.net.packet.PacketProcessor;
import org.onosproject.net.packet.PacketContext;
import org.onlab.packet.Ethernet;
import org.onosproject.net.packet.PacketPriority;
import org.onosproject.net.packet.PacketService;
import org.onosproject.net.packet.InboundPacket;
import org.onosproject.net.PortNumber;
import org.onosproject.net.Device;
import org.onosproject.net.flow.TrafficSelector;
import org.onosproject.net.flow.DefaultTrafficSelector;
import org.onlab.packet.TpPort; // for port number
// config listener
import org.onosproject.net.config.ConfigFactory;
import org.onosproject.net.config.NetworkConfigEvent;
import org.onosproject.net.config.NetworkConfigListener;
import org.onosproject.net.config.NetworkConfigRegistry;
import static org.onosproject.net.config.NetworkConfigEvent.Type.CONFIG_ADDED;
import static org.onosproject.net.config.NetworkConfigEvent.Type.CONFIG_UPDATED;
import static org.onosproject.net.config.basics.SubjectFactories.APP_SUBJECT_FACTORY;
// intent service
//import org.onosproject.net.intent.PointToPointIntent;
import org.onosproject.net.intent.IntentService;
import org.onosproject.net.intent.PointToPointIntent;
import org.onosproject.net.intent.Key;
import org.onosproject.net.intent.Intent;
//sup
import org.onosproject.core.ApplicationId;
import org.onosproject.core.CoreService;
import org.onosproject.net.DeviceId;
import org.onosproject.net.flow.TrafficTreatment;
import org.onosproject.net.flow.DefaultTrafficTreatment;
import java.util.Set;
import java.util.HashSet;
/**
 * Skeletal ONOS application component.
 */
@Component(immediate = true)
public class AppComponent {

    private final Logger log = LoggerFactory.getLogger(getClass());
    private final NameConfigListener cfgListener = new NameConfigListener();
    private final ConfigFactory<ApplicationId, NameConfig> factory = new ConfigFactory<ApplicationId, NameConfig>(
        APP_SUBJECT_FACTORY, NameConfig.class, "UnicastDhcpConfig") {
        @Override
        public NameConfig createConfig() {
        return new NameConfig();
        }
    };
    private ApplicationId appId;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected CoreService coreService;
    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected ComponentConfigService cfgService;

    // packet service
    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected PacketService packetService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected NetworkConfigRegistry networkConfigRegistry;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected DeviceService deviceService;

    // store serverLocation
    private String serverLocation;
    // parsed server connect point
    private ConnectPoint serverConnectPoint;
    // track installed intents to avoid duplicates and for cleanup
    private final Set<Key> installedIntentKeys = new HashSet<>();

    // intent service
    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected IntentService intentService;

    @Activate
    protected void activate() {
        appId = coreService.registerApplication("nycu.winlab.unicastdhcp");
        // add name config listener
        networkConfigRegistry.addListener(cfgListener);
        // add name config factory
        networkConfigRegistry.registerConfigFactory(factory);
        log.info("Started");
        // request DHCP packets
        TrafficSelector.Builder selectorDhcp = DefaultTrafficSelector.builder();
        selectorDhcp.matchEthType(Ethernet.TYPE_IPV4)
            .matchIPProtocol((byte) 17)
            .matchUdpDst(TpPort.tpPort(67));
        packetService.requestPackets(selectorDhcp.build(), PacketPriority.REACTIVE, appId);
        // add packet processor
        packetService.addProcessor(processor, PacketProcessor.director(2));
    }

    @Deactivate
    protected void deactivate() {
        // remove name config listener
        networkConfigRegistry.removeListener(cfgListener);
        // unregister name config factory
        networkConfigRegistry.unregisterConfigFactory(factory);
        // cancel DHCP packets
        TrafficSelector.Builder selectorDhcp = DefaultTrafficSelector.builder();
        selectorDhcp.matchEthType(Ethernet.TYPE_IPV4)
            .matchIPProtocol((byte) 17)
            .matchUdpDst(TpPort.tpPort(67));
        packetService.cancelPackets(selectorDhcp.build(), PacketPriority.REACTIVE, appId);
        // remove packet processor
        packetService.removeProcessor(processor);
        // withdraw installed intents
        for (Key key : installedIntentKeys) {
            Intent existing = intentService.getIntent(key);
            if (existing != null) {
                intentService.withdraw(existing);
            }
        }
        installedIntentKeys.clear();
        log.info("Stopped");
    }
    private final PacketProcessor processor = new DhcpPacketProcessor();
    private class DhcpPacketProcessor implements PacketProcessor {
        @Override
        public void process(PacketContext context) {
            // 如果這個封包已經被處理過，就直接忽略，避免重複處理
            if (context.isHandled()) {
                return;
            }

            InboundPacket pkt = context.inPacket();
            Ethernet ethPkt = pkt.parsed();

            // 如果封包無法解析成乙太網路封包，就忽略
            if (ethPkt == null) {
                return;
            }
            // get server location and packet-in port and device
            String serverLoc = AppComponent.this.serverLocation;
            ConnectPoint receivedFrom = pkt.receivedFrom();
            DeviceId deviceId = receivedFrom.deviceId();
            PortNumber port = receivedFrom.port();
            log.info("DHCP Server location is {}!, Packet-in port is {}!, Device is {}!", serverLoc, port, deviceId);

            // 若 server 位置尚未設定，無法建 intent
            if (serverConnectPoint == null) {
                log.warn("Server ConnectPoint not set; skip installing intents");
                return;
            }
            // 以收到封包的接點作為 client 端，建立雙向 DHCP intents
            installBidirectionalDhcpIntents(receivedFrom, serverConnectPoint);
        }
    }
    /**
     * 使用 PointToPointIntent 建立 client<->server 雙向 DHCP intents。
     * 一個匹配 client->server (UDP 68->67)，另一個匹配 server->client (UDP 67->68)。
     */
    private void installBidirectionalDhcpIntents(ConnectPoint clientCp, ConnectPoint serverCp) {
        // client -> server selector
        TrafficSelector.Builder selForward = DefaultTrafficSelector.builder()
                .matchEthType(Ethernet.TYPE_IPV4)
                .matchIPProtocol((byte) 17)
                .matchUdpSrc(TpPort.tpPort(68))
                .matchUdpDst(TpPort.tpPort(67));
        // server -> client selector
        TrafficSelector.Builder selReverse = DefaultTrafficSelector.builder()
                .matchEthType(Ethernet.TYPE_IPV4)
                .matchIPProtocol((byte) 17)
                .matchUdpSrc(TpPort.tpPort(67))
                .matchUdpDst(TpPort.tpPort(68));
        TrafficTreatment treatment = DefaultTrafficTreatment.builder().build();

        // keys
        Key keyForward = Key.of("dhcp-" + clientCp.toString() + "->" + serverCp.toString(), appId);
        Key keyReverse = Key.of("dhcp-" + serverCp.toString() + "->" + clientCp.toString(), appId);

        // client -> server
        if (!installedIntentKeys.contains(keyForward)) {
            PointToPointIntent forward = PointToPointIntent.builder()
                    .appId(appId)
                    .key(keyForward)
                    .selector(selForward.build())
                    .treatment(treatment)
                    .ingressPoint(clientCp)
                    .egressPoint(serverCp)
                    .build();
            intentService.submit(forward);
            installedIntentKeys.add(keyForward);
            log.info("Submitted DHCP forward intent {} -> {}", clientCp, serverCp);
        }
        // server -> client
        if (!installedIntentKeys.contains(keyReverse)) {
            PointToPointIntent reverse = PointToPointIntent.builder()
                    .appId(appId)
                    .key(keyReverse)
                    .selector(selReverse.build())
                    .treatment(treatment)
                    .ingressPoint(serverCp)
                    .egressPoint(clientCp)
                    .build();
            intentService.submit(reverse);
            installedIntentKeys.add(keyReverse);
            log.info("Submitted DHCP reverse intent {} -> {}", serverCp, clientCp);
        }
    }
    private class NameConfigListener implements NetworkConfigListener {
        @Override
        public void event(NetworkConfigEvent event) {
            if ((event.type() == CONFIG_ADDED || event.type() == CONFIG_UPDATED)
                && event.configClass().equals(NameConfig.class)) {
                NameConfig config = networkConfigRegistry.getConfig(appId, NameConfig.class);
                if (config != null) {
                serverLocation = config.serverLocation();
                /*
                      "UnicastDhcpConfig": {
        "serverLocation": "of:0000000000000003/2"
      }*/
                String serverLocation = config.serverLocation();
                String[] parts = serverLocation.split("/");
                String deviceId = parts[0];
                String portId = parts[1];
                Device device = deviceService.getDevice(DeviceId.deviceId(deviceId));
                PortNumber port = PortNumber.portNumber(Long.parseLong(portId));
                // 快取為 ConnectPoint 以供 intents 使用
                AppComponent.this.serverConnectPoint = new ConnectPoint(DeviceId.deviceId(deviceId), port);
                log.info("DHCP server is connected to `{}`, port `{}`!", device.id(), port);
                }
            }
        }
    }
}
