all: intP4

intP4: intP4.p4
	p4c-bm2-ss --arch v1model -o intP4.json --p4runtime-file intP4.p4info --p4runtime-format text intP4.p4

psa: intP4psa.p4
	p4c-bm2-ss --arch psa -o intP4psa.json --p4runtime-file intP4psa.p4info --p4runtime-format text intP4psa.p4
