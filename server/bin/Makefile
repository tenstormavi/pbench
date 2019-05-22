top=/var/tmp/pbench-test-server/test-9.3/

one:
	PYTHONPATH=$(top)/opt/pbench-server/lib CONFIG=$(top)/opt/pbench-server/lib/config/pbench-server.cfg python3 s3-test.py

conf:
	CONFIG=$(top)/opt/pbench-server/lib/config/pbench-server.cfg getconf.py -d
