#! /usr/bin/env python3
# -*- coding: utf-8 -*-

"""
"""
import sys
import os
from argparse import ArgumentParser
from s3backup import S3Config, Entry
from pbench import init_report_template, report_status, _rename_tb_link, \
    PbenchConfig, BadConfig, get_es, get_pbench_logger, md5sum

def main(args):
    cfg_name = os.environ.get("CONFIG")

    config = PbenchConfig(cfg_name)
    s3_obj = S3Config(config)
    print(s3_obj.connector.path, s3_obj.bucket_name)
    resp = s3_obj.connector.list_objects(s3_obj.bucket_name)
    for obj in resp['Contents']:
        sys.stdout.write("{}\n".format(obj['Key']))

    return 0

if __name__ == '__main__':
    parser = ArgumentParser()
    parser.add_argument("-f", "--file", dest="filename",
                      help="write report to FILE", metavar="FILE")
    parser.add_argument("-q", "--quiet",
                      action="store_false", dest="verbose", default=True,
                      help="don't print status messages to stdout")

    args = parser.parse_args()
    status = main(args)
    sys.exit(status)
