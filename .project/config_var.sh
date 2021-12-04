#!/bin/bash
source .project/yaml.sh
create_variables ./config.yml
eval $(printf "echo $%s" "$1")
