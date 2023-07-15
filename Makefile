run-nektos-act:
	./run-nektos-act.sh

act:
	rm -rf /tmp/artifacts
	act workflow_dispatch \
		-P ubuntu-latest=catthehacker/ubuntu:act-22.04 \
		--artifact-server-path /tmp/artifacts \
		--eventpath .github/act-event.json

