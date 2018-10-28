Run on the onos-p4-dev VM:

• Execute onos-setup-p4-dev

• From inside the Onos directory execute
	ONOS_APPS=proxyarp,lldpprovider,hostprovider,drivers.bmv2,intP4.pipeconf,intP4.intP4app ok clean

• In another console tab start the Onos CLI by executing 
	onos localhost

• In the Onos CLI check the activated apps with apps -a -s (INT P4 pipeconf and INT P4 application must be present)

• In the Onos CLI execute 
	cfg set org.onosproject.net.flow.impl.FlowRuleManager fallbackFlowPollFrequency 5

• In another console tab simulate a network with Mininet by executing 
	sudo -E mn --custom $BMV2_MN_PY --switch onosbmv2,pipeconf=intP4-pipeconf --controller remote,ip=127.0.0.1 
(this command creates a network with one BMV2 switch, that supports P4Runtime and is configured with the pipeline specified in the intP4.p4 program)

• In the Onos CLI check the connected devices with devices -s

• In the Onos GUI check the configuration of the device (Flow Rules, Pipeline Model)

• In the Mininet CLI execute a pingall and then check the new Flow Rules installed in the device