/*
    Created by Alessandra Fais
    SDN part of the RTT course
    MCSN - University of Pisa
    A.A. 2017/18
 */

package org.onosproject.intP4.pipeconf;

import org.apache.felix.scr.annotations.Activate;
import org.apache.felix.scr.annotations.Component;
import org.apache.felix.scr.annotations.Deactivate;
import org.apache.felix.scr.annotations.Reference;
import org.apache.felix.scr.annotations.ReferenceCardinality;
import org.onosproject.driver.pipeline.DefaultSingleTablePipeline;
import org.onosproject.net.behaviour.Pipeliner;
import org.onosproject.net.device.PortStatisticsDiscovery;
import org.onosproject.net.pi.model.DefaultPiPipeconf;
import org.onosproject.net.pi.model.PiPipeconf;
import org.onosproject.net.pi.model.PiPipeconfId;
import org.onosproject.net.pi.model.PiPipelineInterpreter;
import org.onosproject.net.pi.model.PiPipelineModel;
import org.onosproject.net.pi.service.PiPipeconfService;
import org.onosproject.p4runtime.model.P4InfoParser;
import org.onosproject.p4runtime.model.P4InfoParserException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.URL;

import static org.onosproject.net.pi.model.PiPipeconf.ExtensionType.BMV2_JSON;
import static org.onosproject.net.pi.model.PiPipeconf.ExtensionType.P4_INFO_TEXT;

/**
 * IntP4 app: component that produces and registers a pipeconf when loaded.
 */
@Component(immediate = true)
public final class PipeconfFactory {

    private final Logger log = LoggerFactory.getLogger(getClass());

    public static final PiPipeconfId PIPECONF_ID = new PiPipeconfId("intP4-pipeconf");
    private static final URL P4INFO_URL = PipeconfFactory.class.getResource("/intP4.p4info");
    private static final URL BMV2_JSON_URL = PipeconfFactory.class.getResource("/intP4.json");

    @Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
    private PiPipeconfService piPipeconfService;

	/*
	 * Registers the pipeconf at the component activation.
	 */
    @Activate
    public void activate() {
        try {
            piPipeconfService.register(buildPipeconf());
        } catch (P4InfoParserException e) {
            log.error("Fail to register {} - Exception: {} - Cause: {}",
                    PIPECONF_ID, e.getMessage(), e.getCause().getMessage());
        }
    }

	/*
	 * Unregisters the pipeconf at the component deactivation.
	 */
    @Deactivate
    public void deactivate() {
        try {
            piPipeconfService.remove(PIPECONF_ID);
        } catch (IllegalStateException e) {
            log.warn("{} haven't been registered", PIPECONF_ID);
        }
    }

	/*
	 * Builds the pipeline as specified in the intP4.p4.
	 */
    private PiPipeconf buildPipeconf() throws P4InfoParserException {

        final PiPipelineModel pipelineModel = P4InfoParser.parse(P4INFO_URL);

        return DefaultPiPipeconf.builder()
                .withId(PIPECONF_ID)
                .withPipelineModel(pipelineModel)
                .addBehaviour(PiPipelineInterpreter.class, PipelineInterpreterImpl.class)
                .addBehaviour(PortStatisticsDiscovery.class, PortStatisticsDiscoveryImpl.class)
                .addBehaviour(Pipeliner.class, DefaultSingleTablePipeline.class)
                .addExtension(P4_INFO_TEXT, P4INFO_URL)
                .addExtension(BMV2_JSON, BMV2_JSON_URL)
                .build();
    }
}
