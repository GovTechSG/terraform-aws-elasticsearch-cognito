# TODO: Make include a dynamic loaded variable instead of hardcoding ../../../
define HELP
# eks
Module for elasticsearch, only make doc is supported for modules

endef
export HELP

doc:
	@bash ./scripts/terraform-doc.sh md

fmt:
	@terraform fmt

init:
	@terraform init
