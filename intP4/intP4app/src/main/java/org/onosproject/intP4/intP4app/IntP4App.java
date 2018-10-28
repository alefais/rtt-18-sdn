/*
    Created by Alessandra Fais
    SDN part of the RTT course
    MCSN - University of Pisa
    A.A. 2017/18
 */

package org.onosproject.intP4.intP4app;

import com.google.common.collect.Lists;
import org.apache.felix.scr.annotations.Activate;
import org.apache.felix.scr.annotations.Component;
import org.apache.felix.scr.annotations.Deactivate;
import org.apache.felix.scr.annotations.Reference;
import org.apache.felix.scr.annotations.ReferenceCardinality;
import org.onlab.packet.IpAddress;
import org.onosproject.core.ApplicationId;
import org.onosproject.core.CoreService;
import org.onosproject.net.DeviceId;
import org.onosproject.net.Host;
import org.onosproject.net.Link;
import org.onosproject.net.Path;
import org.onosproject.net.PortNumber;
import org.onosproject.net.flow.DefaultFlowRule;
import org.onosproject.net.flow.DefaultTrafficSelector;
import org.onosproject.net.flow.DefaultTrafficTreatment;
import org.onosproject.net.flow.FlowRule;
import org.onosproject.net.flow.FlowRuleService;
import org.onosproject.net.flow.criteria.PiCriterion;
import org.onosproject.net.host.HostEvent;
import org.onosproject.net.host.HostListener;
import org.onosproject.net.host.HostService;
import org.onosproject.net.pi.model.PiActionId;
import org.onosproject.net.pi.model.PiActionParamId;
import org.onosproject.net.pi.model.PiMatchFieldId;
import org.onosproject.net.pi.model.PiTableId;
import org.onosproject.net.pi.runtime.PiAction;
import org.onosproject.net.pi.runtime.PiActionParam;
import org.onosproject.net.topology.Topology;
import org.onosproject.net.topology.TopologyService;
import org.slf4j.Logger;

import java.util.Collections;
import java.util.List;
import java.util.Random;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;

import static org.slf4j.LoggerFactory.getLogger;

/**
 * IntP4App application provides In-band Network Telemetry (INT)
 * between each pair of hosts as defined in intP4.p4.
 * <p>
 * The app works by listening for host events. Each time a new host is
 * discovered, it evaluates a path between that host and all the others, and
 * the latency of the packets that travel each path is measured.
 */
@Component(immediate = true)
public class IntP4App {

    private static final String APP_NAME = "org.onosproject.intP4.intP4app";

    // Flow rules installed with default priority
    private static final int FLOW_RULE_PRIORITY = 100;

    private static final Logger log = getLogger(IntP4App.class);
    private final HostListener hostListener = new InternalHostListener();
    private ApplicationId appId;
    private AtomicInteger nextINTpathId = new AtomicInteger();

    /*
     * ONOS core services needed by this application.
     */
    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    private FlowRuleService flowRuleService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    private CoreService coreService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    private TopologyService topologyService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    private HostService hostService;

    /*
     * Registers app and event listeners.
     */
    @Activate
    public void activate() {
        log.info("Starting...");
        appId = coreService.registerApplication(APP_NAME);
        hostService.addListener(hostListener);
        log.info("STARTED", appId.id());
    }

    /*
     * Removes listeners and cleans up flow rules.
     */
    @Deactivate
    public void deactivate() {
        log.info("Stopping...");
        hostService.removeListener(hostListener);
        flowRuleService.removeFlowRulesById(appId);
        log.info("STOPPED");
    }

    /**
     * Sets an INT path between the given source and destination host with
     * the given INT path ID: a randomly picked shortest path is chosen,
     * based on the given topology snapshot.
     *
     * @param pathId: INT path ID
     * @param srcHost: INT path source host
     * @param dstHost: INT path destination host
     * @param topo: network topology snapshot
     */
    private void provisionINTpath(int pathId, Host srcHost, Host dstHost, Topology topo) {

        // Get all shortest paths between switches connected to source and destination hosts
        DeviceId srcSwitch = srcHost.location().deviceId();
        DeviceId dstSwitch = dstHost.location().deviceId();

        List<Link> pathLinks;
        if (srcSwitch.equals(dstSwitch)) { // Source and dest hosts connected to the same switch
            pathLinks = Collections.emptyList();
        } else { // Compute shortest path
            Set<Path> allPaths = topologyService.getPaths(topo, srcSwitch, dstSwitch);
            if (allPaths.size() == 0) {
                log.warn("No paths between {} and {}", srcHost.id(), dstHost.id());
                return;
            }
            // If many shortest paths are available, pick one at random
            pathLinks = pickRandomPath(allPaths).links();
        }

        // Insert path ingress rules toward each IP dest address (next switches in the path will forward based on path ID only)
        for (IpAddress dstIpAddr : dstHost.ipAddresses()) {
            insertINTpathIngressRule(srcSwitch, dstIpAddr, pathId);
        }

        // Insert path transit rules on all switches in the path (excluded the last one - the egress)
        for (Link link : pathLinks) {
            DeviceId sw = link.src().deviceId();
            PortNumber port = link.src().port();
            insertINTpathForwardRule(sw, port, pathId, false);
        }

        // Insert path transit rule for the path egress switch
        PortNumber egressSwitchPort = dstHost.location().port();
        insertINTpathForwardRule(dstSwitch, egressSwitchPort, pathId, true);

        log.info("** Completed provisioning of INT path {} (srcHost={} dstHost={})",
                 pathId, srcHost.id(), dstHost.id());
    }

    /**
     * Generates and inserts a flow rule to perform the INT path INGRESS function
     * for the given switch, destination IP address and INT path ID.
     *
     * @param switchId: switch ID
     * @param dstIpAddr: IP address to forward inside the INT path
     * @param pathId: INT path ID
     */
    private void insertINTpathIngressRule(DeviceId switchId, IpAddress dstIpAddr, int pathId) {

        PiTableId pathIngressTableId = PiTableId.of("c_ingress.t_int_ingress");

        // Longest prefix match on IPv4 dest address
        PiMatchFieldId ipDestMatchFieldId = PiMatchFieldId.of("headers.ipv4_hdr.dst_addr");
        PiCriterion match = PiCriterion.builder()
        			        .matchLpm(ipDestMatchFieldId, dstIpAddr.toOctets(), 32)
                			.build();

		// Action parameter
        PiActionParam pathIdParam = new PiActionParam(PiActionParamId.of("path_id"), pathId);

		// Action
        PiActionId ingressActionId = PiActionId.of("c_ingress.int_ingress");
        PiAction action = PiAction.builder()
                			.withId(ingressActionId)
        			        .withParameter(pathIdParam)
                			.build();

        log.info("Inserting INGRESS rule on switch {}: table={}, match={}, action={}",
                 switchId, pathIngressTableId, match, action);

        insertPiFlowRule(switchId, pathIngressTableId, match, action);
    }

    /**
     * Generates and insert a flow rule to perform the INT path FORWARD/EGRESS
     * function for the given switch, output port number and INT path ID.
     *
     * @param switchId: switch ID
     * @param outPort: output port where to forward packets in the INT path
     * @param pathId: INT path ID
     * @param isEgress: if true, perform INT path egress action on the given outPort,
     *                  otherwise forward packet with a set_out_port action
     */
    private void insertINTpathForwardRule(DeviceId switchId, PortNumber outPort, int pathId, boolean isEgress) {

        PiTableId pathForwardTableId = PiTableId.of("c_ingress.t_int_fwd");

        // Exact match on path ID
        PiMatchFieldId pathIdMatchFieldId = PiMatchFieldId.of("headers.int_hdr.path_id");
        PiCriterion match = PiCriterion.builder()
                			.matchExact(pathIdMatchFieldId, pathId)
               			    .build();

        // Action parameter
        PiActionParamId portParamId = PiActionParamId.of("port");
        PiActionParam portParam = new PiActionParam(portParamId, (short) outPort.toLong());

		// Action
        final PiAction action;
        if (isEgress) {
            PiActionId egressActionId = PiActionId.of("c_ingress.int_egress");
            action = PiAction.builder()
                     .withId(egressActionId)
                     .withParameter(portParam)
                     .build();
        } else {
			PiActionId outPortActionId = PiActionId.of("c_ingress.set_out_port");
            action = PiAction.builder()
                     .withId(outPortActionId)
                     .withParameter(portParam)
                     .build();
        }

        log.info("Inserting {} rule on switch {}: table={}, match={}, action={}",
                 isEgress ? "EGRESS" : "TRANSIT",
                 switchId, pathForwardTableId, match, action);

        insertPiFlowRule(switchId, pathForwardTableId, match, action);
    }

    /**
     * Inserts a flow rule.
     *
     * @param switchId: switch ID
     * @param tableId: table ID
     * @param piCriterion: PI criterion
     * @param piAction: PI action
     */
    private void insertPiFlowRule(DeviceId switchId, PiTableId tableId, PiCriterion piCriterion, PiAction piAction) {
        FlowRule rule = DefaultFlowRule.builder()
                		.forDevice(switchId)
        		        .forTable(tableId)
                		.fromApp(appId)
                		.withPriority(FLOW_RULE_PRIORITY)
                		.makePermanent()
                		.withSelector(DefaultTrafficSelector.builder().matchPi(piCriterion).build())
                		.withTreatment(DefaultTrafficTreatment.builder().piTableAction(piAction).build())
                		.build();
        flowRuleService.applyFlowRules(rule);
    }

	/*
	 * Generates a unique ID for a new path.
	 */
    private int getNewINTpathId() {
        return nextINTpathId.incrementAndGet();
    }

	/*
	 * Selects a random path from all the paths found between the current source and dest hosts.
	 */
    private Path pickRandomPath(Set<Path> paths) {
        int item = new Random().nextInt(paths.size());
        List<Path> pathList = Lists.newArrayList(paths);
        return pathList.get(item);
    }

    /**
     * A listener of host events that provisions two INT paths for each pair of
     * hosts when a new host is discovered.
     */
    private class InternalHostListener implements HostListener {

        @Override
        public void event(HostEvent event) {
            if (event.type() != HostEvent.Type.HOST_ADDED) { // ignore events different from HOST_ADDED
                return;
            }
            synchronized (this) { // synchronizing for developing purposes
                Host host = event.subject();
                Topology topo = topologyService.currentTopology();
                for (Host otherHost : hostService.getHosts()) {
                    if (!host.equals(otherHost)) {
                        provisionINTpath(getNewINTpathId(), host, otherHost, topo);
                        provisionINTpath(getNewINTpathId(), otherHost, host, topo);
                    }
                }
            }
        }
    }
}
