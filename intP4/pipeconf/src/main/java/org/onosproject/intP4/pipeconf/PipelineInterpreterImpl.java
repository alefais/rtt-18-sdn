/*
     Created by Alessandra Fais
     SDN part of the RTT course
     MCSN - University of Pisa
     A.A. 2017/18
 */

package org.onosproject.intP4.pipeconf;

import com.google.common.collect.BiMap;
import com.google.common.collect.ImmutableBiMap;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.Lists;
import org.onlab.packet.DeserializationException;
import org.onlab.packet.Ethernet;
import org.onlab.util.ImmutableByteSequence;
import org.onosproject.net.ConnectPoint;
import org.onosproject.net.DeviceId;
import org.onosproject.net.Port;
import org.onosproject.net.PortNumber;
import org.onosproject.net.device.DeviceService;
import org.onosproject.net.driver.AbstractHandlerBehaviour;
import org.onosproject.net.flow.TrafficTreatment;
import org.onosproject.net.flow.criteria.Criterion;
import org.onosproject.net.flow.instructions.Instruction;
import org.onosproject.net.flow.instructions.Instructions.OutputInstruction;
import org.onosproject.net.packet.DefaultInboundPacket;
import org.onosproject.net.packet.InboundPacket;
import org.onosproject.net.packet.OutboundPacket;
import org.onosproject.net.pi.model.PiActionId;
import org.onosproject.net.pi.model.PiActionParamId;
import org.onosproject.net.pi.model.PiControlMetadataId;
import org.onosproject.net.pi.model.PiMatchFieldId;
import org.onosproject.net.pi.model.PiPipelineInterpreter;
import org.onosproject.net.pi.model.PiTableId;
import org.onosproject.net.pi.runtime.PiAction;
import org.onosproject.net.pi.runtime.PiActionParam;
import org.onosproject.net.pi.runtime.PiControlMetadata;
import org.onosproject.net.pi.runtime.PiPacketOperation;

import java.nio.ByteBuffer;
import java.util.Collection;
import java.util.List;
import java.util.Optional;

import static java.lang.String.format;
import static org.onlab.util.ImmutableByteSequence.copyFrom;
import static org.onosproject.net.PortNumber.CONTROLLER;
import static org.onosproject.net.PortNumber.FLOOD;
import static org.onosproject.net.flow.instructions.Instruction.Type.OUTPUT;
import static org.onosproject.net.pi.model.PiPacketOperationType.PACKET_OUT;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * IntP4 app: implementation of a pipeline interpreter for the intP4.p4 program.
 */
public final class PipelineInterpreterImpl extends AbstractHandlerBehaviour implements PiPipelineInterpreter {

	private final Logger log = LoggerFactory.getLogger(getClass());
	
	// Mapping between ONOS strings and intP4.p4 names.
    private static final String DOT = ".";
    private static final String HDR = "headers";
    private static final String C_INGRESS = "c_ingress";
    private static final String T_L2_FWD = "t_l2_fwd";
    private static final String EGRESS_PORT = "egress_port";
    private static final String INGRESS_PORT = "ingress_port";
    private static final String ETHERNET = "eth_hdr";
    private static final String STANDARD_METADATA = "standard_meta";
    private static final String INGRESS_TIME = "ingress_global_timestamp";
    private static final String EGRESS_TIME = "egress_global_timestamp";
    private static final String PACKET_IN_TYPE = "packet_in_type";
    private static final int PORT_FIELD_BITWIDTH = 9;

    private static final String C_EGRESS = "c_egress";
    private static final String T_INT_EGRESS = "t_int_egress";

	// Defines matches for t_l2_fwd.
    private static final PiMatchFieldId INGRESS_PORT_ID = PiMatchFieldId.of(STANDARD_METADATA + DOT + INGRESS_PORT);
    private static final PiMatchFieldId ETH_DST_ID = PiMatchFieldId.of(HDR + DOT + ETHERNET + DOT + "dst_addr");
    private static final PiMatchFieldId ETH_SRC_ID = PiMatchFieldId.of(HDR + DOT + ETHERNET + DOT + "src_addr");
    private static final PiMatchFieldId ETH_TYPE_ID = PiMatchFieldId.of(HDR + DOT + ETHERNET + DOT + "ether_type");

	// Defines table t_l2_fwd.
    private static final PiTableId TABLE_L2_FWD_ID = PiTableId.of(C_INGRESS + DOT + T_L2_FWD);

    // Defines table t_int_egress.
    private static final PiTableId TABLE_INT_EGRESS_ID = PiTableId.of(C_EGRESS + DOT + T_INT_EGRESS);

	// Defines actions for t_l2_fwd and t_int_egress.
    private static final PiActionId ACT_ID_NOP = PiActionId.of("NoAction");
    private static final PiActionId ACT_ID_SEND_TO_CPU = PiActionId.of(C_INGRESS + DOT + "send_to_cpu");
    private static final PiActionId ACT_ID_SET_EGRESS_PORT = PiActionId.of(C_INGRESS + DOT + "set_out_port");
    private static final PiActionId ACT_ID_SEND_CLONE_TO_CPU = PiActionId.of(C_EGRESS + DOT + "send_clone_to_cpu");

	// Defines parameter for action send_to_cpu.
    private static final PiActionParamId ACT_PARAM_ID_PORT = PiActionParamId.of("port");

	// Maps table t_l2_fwd into device's table 0 and table t_int_egress into device's table 1.
    private static final BiMap<Integer, PiTableId> TABLE_MAP =
    				        new ImmutableBiMap.Builder<Integer, PiTableId>()
                    		.put(0, TABLE_L2_FWD_ID)
                            .put(1, TABLE_INT_EGRESS_ID)
                    		.build();

	// Maps t_l2_fw2 match fields to ONOS criteria.
    private static final BiMap<Criterion.Type, PiMatchFieldId> CRITERION_MAP =
            				new ImmutableBiMap.Builder<Criterion.Type, PiMatchFieldId>()
                    		.put(Criterion.Type.IN_PORT, INGRESS_PORT_ID)
                    		.put(Criterion.Type.ETH_DST, ETH_DST_ID)
                    		.put(Criterion.Type.ETH_SRC, ETH_SRC_ID)
                    		.put(Criterion.Type.ETH_TYPE, ETH_TYPE_ID)
                    		.build();

	/*
	 * Returns the header field ID defined in intP4.p4 mapped to the specified criterion.
	 */
    @Override
    public Optional<PiMatchFieldId> mapCriterionType(Criterion.Type type) {
        return Optional.ofNullable(CRITERION_MAP.get(type));
    }

	/*
	 * Returns the criterion mapped to the specified header field ID defined in intP4.p4.
	 */
    @Override
    public Optional<Criterion.Type> mapPiMatchFieldId(PiMatchFieldId headerFieldId) {
        return Optional.ofNullable(CRITERION_MAP.inverse().get(headerFieldId));
    }

	/*
	 * Returns the table ID defined in intP4.p4 mapped to the specified int table ID.
	 */
    @Override
    public Optional<PiTableId> mapFlowRuleTableId(int flowRuleTableId) {
        return Optional.ofNullable(TABLE_MAP.get(flowRuleTableId));
    }

	/*
	 * Returns the int table ID mapped to the specified table ID defined in intP4.p4.
	 */
    @Override
    public Optional<Integer> mapPiTableId(PiTableId piTableId) {
        return Optional.ofNullable(TABLE_MAP.inverse().get(piTableId));
    }

	/*
	 * Maps t_l2_fw2 and t_int_egress actions and ONOS treatments.
	 */
    @Override
    public PiAction mapTreatment(TrafficTreatment treatment, PiTableId piTableId) throws PiInterpreterException {
        if (piTableId == TABLE_L2_FWD_ID) {
            if (treatment.allInstructions().size() == 0) { // Case "NoAction"
                return PiAction.builder().withId(ACT_ID_NOP).build();
            } else if (treatment.allInstructions().size() > 1) { // Treatments with only 1 instruction are managed
                throw new PiInterpreterException("Treatment has multiple instructions");
            }

            // Get the first and only instruction.
            Instruction instruction = treatment.allInstructions().get(0);

            // Only instructions of type OUTPUT are mapped.
            if (instruction.type() != OUTPUT) {
                throw new PiInterpreterException(format("Instruction of type '%s' not supported", instruction.type()));
            }

            OutputInstruction outInstruction = (OutputInstruction) instruction;
            PortNumber port = outInstruction.port();
            if (!port.isLogical()) {
                return PiAction.builder()
                        .withId(ACT_ID_SET_EGRESS_PORT)
                        .withParameter(new PiActionParam(ACT_PARAM_ID_PORT, copyFrom(port.toLong())))
                        .build();
            } else if (port.equals(CONTROLLER)) {
                return PiAction.builder()
                        .withId(ACT_ID_SEND_TO_CPU)
                        .build();
            } else {
                throw new PiInterpreterException(format("Output on logical port '%s' not supported", port));
            }
        } else if (piTableId == TABLE_INT_EGRESS_ID) {
            if (treatment.allInstructions().size() == 0) { // Case "NoAction"
                return PiAction.builder().withId(ACT_ID_NOP).build();
            } else if (treatment.allInstructions().size() > 1) { // Treatments with only 1 instruction are managed
                throw new PiInterpreterException("Treatment has multiple instructions");
            }

            // Get the first and only instruction.
            Instruction instruction = treatment.allInstructions().get(0);

            // Only instructions of type OUTPUT are mapped.
            if (instruction.type() != OUTPUT) {
                throw new PiInterpreterException(format("Instruction of type '%s' not supported", instruction.type()));
            }

            OutputInstruction outInstruction = (OutputInstruction) instruction;
            PortNumber port = outInstruction.port();
            if (port.isLogical() && port.equals(CONTROLLER)) {
                return PiAction.builder()
                        .withId(ACT_ID_SEND_CLONE_TO_CPU)
                        .build();
            } else {
                throw new PiInterpreterException(format("Output on logical port '%s' not supported", port));
            }
        } else {
            throw new PiInterpreterException("Can map treatments only for 't_l2_fwd' and 't_int_egress' tables");
        }
    }

	/*
	 * Maps packet tratment instructions into a list of PI packet operations for a packet out
	 * sent from the controller to the device.
	 */
    @Override
    public Collection<PiPacketOperation> mapOutboundPacket(OutboundPacket packet) throws PiInterpreterException {
        TrafficTreatment treatment = packet.treatment();

        // Only packet-out with OUTPUT instructions is supported.
        if (treatment.allInstructions().size() != 1 && treatment.allInstructions().get(0).type() != OUTPUT) {
            throw new PiInterpreterException("Treatment not supported: " + treatment.toString());
        }

        Instruction instruction = treatment.allInstructions().get(0);
        PortNumber port = ((OutputInstruction) instruction).port();
        List<PiPacketOperation> piPacketOps = Lists.newArrayList();

        if (!port.isLogical()) {
            piPacketOps.add(createPiPacketOp(packet.data(), port.toLong()));
        } else if (port.equals(FLOOD)) { // A packet operation for each switch port is created.
            DeviceService deviceService = handler().get(DeviceService.class);
            DeviceId deviceId = packet.sendThrough();
            for (Port p : deviceService.getPorts(deviceId)) {
                piPacketOps.add(createPiPacketOp(packet.data(), p.number().toLong()));
            }
        } else {
            throw new PiInterpreterException(format("Output on logical port '%s' not supported", port));
        }

        return piPacketOps;
    }

	/*
	 * Maps PI packet content for a packet in received from the device into a ONOS packet in structure.
	 */
    @Override
    public InboundPacket mapInboundPacket(PiPacketOperation packetIn) throws PiInterpreterException {
        // Assume that the packet is ethernet (ok since intP4.p4 deparses only ethernet packets).
        Ethernet ethPkt;

        try {
            ethPkt = Ethernet.deserializer().deserialize(packetIn.data().asArray(), 0, packetIn.data().size());
        } catch (DeserializationException dex) {
            throw new PiInterpreterException(dex.getMessage());
        }

		// Returns the type of the received packet-in
        Optional<PiControlMetadata> packetInTypeMetadata = 
        				packetIn.metadatas().stream()
                		.filter(metadata -> metadata.id().toString().equals(PACKET_IN_TYPE))
                		.findFirst();

		if (packetInTypeMetadata.isPresent()) {
			short type = packetInTypeMetadata.get().value().asReadOnlyBuffer().getShort();
			log.warn("Processed packet-in type: {}", packetInTypeMetadata.toString());

			// Returns the ingress port packet metadata
        	Optional<PiControlMetadata> ingressPortMetadata = 
        				packetIn.metadatas().stream()
                		.filter(metadata -> metadata.id().toString().equals(INGRESS_PORT))
                		.findFirst();

        	if (ingressPortMetadata.isPresent()) {
        	    short p = ingressPortMetadata.get().value().asReadOnlyBuffer().getShort();
				log.warn("Processed packet-in ingress port: {}", ingressPortMetadata.toString());
	            ConnectPoint receivedFrom = new ConnectPoint(packetIn.deviceId(), PortNumber.portNumber(p));

            	if (type == 1) { // Modified packet-in
            		// Returns the ingress and egress timestamps packet metadata
           			Optional<PiControlMetadata> ingressTimeMetadata = packetIn.metadatas().stream()
 	          								.filter(metadata -> metadata.id().toString().equals(INGRESS_TIME))
 	          								.findFirst();
 	            	Optional<PiControlMetadata> egressTimeMetadata = packetIn.metadatas().stream()
 	            							.filter(metadata -> metadata.id().toString().equals(EGRESS_TIME))
 	            							.findFirst();
 	            	// Returns the egress port packet metadata: IDEA->ricevi la egress port e usa la porta ricevuta per creare un packet out ad-hoc (?)
 	            	Optional<PiControlMetadata> egressPortMetadata = packetIn.metadatas().stream()
 	            							.filter(metadata -> metadata.id().toString().equals(EGRESS_PORT))
 	             	   						.findFirst();
           			if (ingressTimeMetadata.isPresent()) {
           				log.warn("Received INT packet-in: {}", ingressTimeMetadata.toString());
           			}
           			if (egressTimeMetadata.isPresent()) {
           				log.warn("Received INT packet-in: {}", egressTimeMetadata.toString());
           			}
           			if (egressTimeMetadata.isPresent()) {
   		   				log.warn("Received INT packet-in: {}", egressPortMetadata.toString());
           			}
           		} else if (type != 0) {
					throw new PiInterpreterException(
   								format("Missing metadata '%s', '%s', '%s' in packet-in received from '%s': %s",
			                   	INGRESS_TIME, EGRESS_TIME, EGRESS_PORT, packetIn.deviceId(), packetIn));
 				}
 				
				return new DefaultInboundPacket(receivedFrom, ethPkt, packetIn.data().asReadOnlyBuffer());
			} else {
				throw new PiInterpreterException(
							format("Missing metadata '%s', '%s', '%s' in packet-in received from '%s': %s",
		                   	INGRESS_PORT, packetIn.deviceId(), packetIn));
		    }
        } else {
            throw new PiInterpreterException(
            			format("Missing metadata '%s' in packet-in received from '%s': %s",
                    	PACKET_IN_TYPE, packetIn.deviceId(), packetIn));
        }
    }

    private PiPacketOperation createPiPacketOp(ByteBuffer data, long portNumber) throws PiInterpreterException {
        PiControlMetadata metadata = createControlMetadata(portNumber);
        return PiPacketOperation.builder()
                .forDevice(this.data().deviceId())
                .withType(PACKET_OUT)
                .withData(copyFrom(data))
                .withMetadatas(ImmutableList.of(metadata))
                .build();
    }

    private PiControlMetadata createControlMetadata(long portNumber) throws PiInterpreterException {
        try {
            return PiControlMetadata.builder()
                    .withId(PiControlMetadataId.of(EGRESS_PORT))
                    .withValue(copyFrom(portNumber).fit(PORT_FIELD_BITWIDTH))
                    .build();
        } catch (ImmutableByteSequence.ByteSequenceTrimException e) {
            throw new PiInterpreterException(format("Port number %d too big, %s", portNumber, e.getMessage()));
        }
    }
}
