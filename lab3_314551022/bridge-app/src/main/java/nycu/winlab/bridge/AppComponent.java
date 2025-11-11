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
package nycu.winlab.bridge;

import org.onosproject.cfg.ComponentConfigService;
import org.osgi.service.component.ComponentContext;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.osgi.service.component.annotations.Modified;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Dictionary;
import java.util.Properties;


import static org.onlab.util.Tools.get;


// packet processing service
import org.onosproject.net.packet.PacketProcessor;
import org.onosproject.net.packet.PacketContext;
import org.onosproject.net.flow.TrafficTreatment;
import org.onosproject.net.flow.DefaultTrafficTreatment;


import org.onlab.packet.Ethernet;
import org.onlab.packet.MacAddress;
import org.onosproject.net.ConnectPoint;
import org.onosproject.net.DeviceId;
import org.onosproject.net.PortNumber;
import org.onosproject.net.packet.InboundPacket;
import org.onosproject.net.packet.PacketPriority;
import org.onosproject.net.packet.PacketService;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import org.onosproject.net.flow.FlowRuleService;
import org.onosproject.net.flow.TrafficSelector;
import org.onosproject.net.flow.DefaultTrafficSelector;
import org.onosproject.net.flow.FlowRule;
import org.onosproject.net.flow.DefaultFlowRule;
import org.onosproject.core.ApplicationId;
import org.onosproject.core.CoreService;
/**
 * Skeletal ONOS application component.
 */
@Component(immediate = true,
           service = {SomeInterface.class},
           property = {
               "someProperty=Some Default String Value",
           })
public class AppComponent implements SomeInterface {

    private final Logger log = LoggerFactory.getLogger(getClass());

    /** Some configurable property. */
    private String someProperty;
    private Map<DeviceId, Map<MacAddress, PortNumber>> macTables = new ConcurrentHashMap<>();

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected ComponentConfigService cfgService;


    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected PacketService packetService;

    // Flow Rule Service
    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected FlowRuleService flowRuleService;

    // Core Service
    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected CoreService coreService;

    // Application ID
    private ApplicationId appId;

    @Activate
    protected void activate() {
        cfgService.registerProperties(getClass());
        // install my app
        appId = coreService.registerApplication("nycu.winlab.bridge");
        log.info("Started");
        // 請求 IPv4 封包的 Packet-in
        TrafficSelector.Builder selectorIpv4 = DefaultTrafficSelector.builder();
        selectorIpv4.matchEthType(Ethernet.TYPE_IPV4);
        packetService.requestPackets(selectorIpv4.build(), PacketPriority.REACTIVE, appId);
        TrafficSelector.Builder selectorArp = DefaultTrafficSelector.builder();
        selectorArp.matchEthType(Ethernet.TYPE_ARP);
        packetService.requestPackets(selectorArp.build(), PacketPriority.REACTIVE, appId);
        packetService.addProcessor(processor, PacketProcessor.director(2));

    }

    @Deactivate
    protected void deactivate() {
        cfgService.unregisterProperties(getClass(), false);
        // 取消 Packet-in 請求
        TrafficSelector.Builder selectorIpv4 = DefaultTrafficSelector.builder();
        selectorIpv4.matchEthType(Ethernet.TYPE_IPV4);
        packetService.cancelPackets(selectorIpv4.build(), PacketPriority.REACTIVE, appId);
        TrafficSelector.Builder selectorArp = DefaultTrafficSelector.builder();
        selectorArp.matchEthType(Ethernet.TYPE_ARP);
        packetService.cancelPackets(selectorArp.build(), PacketPriority.REACTIVE, appId);
        packetService.removeProcessor(processor);
        log.info("Stopped");
    }

    @Modified
    public void modified(ComponentContext context) {
        Dictionary<?, ?> properties = context != null ? context.getProperties() : new Properties();
        if (context != null) {
            someProperty = get(properties, "someProperty");
        }
        log.info("Reconfigured");
    }

    @Override
    public void someMethod() {
        log.info("Invoked");
    }

    private final PacketProcessor processor = new BridgePacketProcessor();

    private class BridgePacketProcessor implements PacketProcessor {

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

            ConnectPoint cp = pkt.receivedFrom();
            DeviceId deviceId = cp.deviceId();
            PortNumber inPort = cp.port();

            MacAddress srcMac = ethPkt.getSourceMAC();
            MacAddress dstMac = ethPkt.getDestinationMAC();

            // --- 1. MAC 位址學習 (Learning) ---
            Map<MacAddress, PortNumber> deviceMacTable = macTables.computeIfAbsent(
                deviceId, k -> new ConcurrentHashMap<>());
            // putIfAbsent 的好處是，只有在 srcMac 真的不存在時才會寫入並回傳 null，這樣可以確保 "Add an entry" 的 Log 只會在第一次學習到時印出一次
            if (deviceMacTable.putIfAbsent(srcMac, inPort) == null) {
                log.info("Add an entry to the port table of {}. MAC address: {} => Port: {}.",
                        deviceId, srcMac, inPort);
            }
            // --- 2. 轉送決策 (Forwarding Decision) ---
            PortNumber outPort = deviceMacTable.get(dstMac);

            if (outPort == null) {
                // 如果在 MAC 表中找不到目的 MAC，代表是 "MAC Miss"，執行廣播
                log.info("MAC address {} is missed on {}. Flood the packet.", dstMac, deviceId);
                flood(context);
            } else {
                // 如果找到了目的 MAC，代表是 "MAC Match"
                // 檢查封包是否從它應該要去的 port 進來，如果是就丟棄，避免網路風暴
                if (outPort.equals(inPort)) {
                    return;
                }
                log.info("MAC address {} is matched on {}. Install a flow rule.", dstMac, deviceId);
                // 步驟 A: 將「當前這個封包」從正確的 port 送出去
                sendPacket(context, outPort);
                // 步驟 B: 為「未來所有」符合的封包安裝一條捷徑 (流規則)
                installFlowRule(deviceId, srcMac, dstMac, outPort);
            }
        }
        //指示交換器將當前封包進行廣播 (Flood)
        private void flood(PacketContext context) {
            context.treatmentBuilder().setOutput(PortNumber.FLOOD);
            context.send();
        }

        //指示交換器將當前封包從指定的 port 送出去
        private void sendPacket(PacketContext context, PortNumber portNumber) {
            context.treatmentBuilder().setOutput(portNumber);
            context.send();
        }

        //在交換器上安裝一條流規則
        private void installFlowRule(DeviceId deviceId, MacAddress srcMac, MacAddress dstMac, PortNumber outPort) {
            // 定義流規則的匹配條件 (Match Fields)
            TrafficSelector selector = DefaultTrafficSelector.builder()
                    .matchEthSrc(srcMac)
                    .matchEthDst(dstMac)
                    .build();

            // 定義流規則的動作 (Action)
            TrafficTreatment treatment = DefaultTrafficTreatment.builder()
                    .setOutput(outPort)
                    .build();

            // 建立流規則物件
            FlowRule flowRule = DefaultFlowRule.builder()
                    .forDevice(deviceId)
                    .withSelector(selector)
                    .withTreatment(treatment)
                    .withPriority(30)
                    .withIdleTimeout(30)
                    .fromApp(appId)
                    .build();
                // 套用流規則到交換器上
            flowRuleService.applyFlowRules(flowRule);
        }
    }
}
