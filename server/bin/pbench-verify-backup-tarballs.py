#!/usr/bin/env python3
# -*- mode: python -*-

import os
import sys
import glob
import hashlib
import shutil
import tempfile
import pathlib
from argparse import ArgumentParser

from pbench import init_report_template, report_status, _rename_tb_link, \
    PbenchConfig, BadConfig, get_es, get_pbench_logger
from s3backup import S3Config, Entry

_NAME_    = "pbench-verify-backup-tarballs"

# Global logger for the module, setup in main()
_logger = None

def checkmd5(target_dir, list_dir, indicator):
    # Function to check integrity of results in a local (archive or local backup) directory
    if not os.path.isdir(target_dir):
        _logger.error('Bad {}: {}'.format(indicator, target_dir))
        os._exit(1)
    tarlist = glob.iglob(os.path.join(target_dir, "*", "*.tar.xz"))
    with open("{}/list.{}".format(list_dir, indicator), 'w') as f_list:
        for tar in tarlist:
            result_name = os.path.basename(tar)
            controller = os.path.basename(os.path.dirname(tar))
            md5 = ("{}.md5".format(tar))
            f_list.write("{}\n".format(result_name))
            with open(md5) as f:
                md5_value = f.readline().split(" ")[0]
            with open(tar, 'rb') as f:
                data = f.read()
                md5_returned = hashlib.md5(data).hexdigest()
            if md5_value == md5_returned:
                with open("{}/list.{}.ok".format(list_dir, indicator), 'w') as f_ok:
                    f_ok.write(
                        "{}/{}: {}\n".format(controller, result_name, "OK"))
            elif md5 != md5_returned:
                with open("{}/list.{}.fail".format(list_dir, indicator), 'w') as f_fail:
                    f_fail.write(
                        "{}/{}: {}\n".format(controller, result_name, "FAILED"))


def report_failed_md5(list_dir, archive, backup, report):
    ret = 0
    archive_fail = '{}/list.archive.fail'.format(list_dir)
    archive_ok = '{}/list.archive.ok'.format(list_dir)
    if os.path.exists(archive_fail) and os.path.getsize(archive_fail) > 0:
        with open(archive_fail) as f:
            failed_list_a = f.read()
        report.write("In Archive: the calculated MD5 of the following entries failed to match the stored MD5:\n{}".format(failed_list_a))
    elif os.path.exists(archive_ok) and os.path.getsize(archive_ok) > 0:
        pass
    else:
        report.write("Archive list is empty - is {} mounted?\n".format(archive))
        ret = 7

    backup_fail = '{}/list.backup.fail'.format(list_dir)
    backup_ok = '{}/list.backup.ok'.format(list_dir)
    if os.path.exists(backup_fail) and os.path.getsize(backup_fail) > 0:
        with open(backup_fail) as f:
            failed_list_b = f.read()
        report.write(
            "In Backup: the calculated MD5 of the following entries failed to match the stored MD5:\n{}".format(failed_list_b))
    elif os.path.exists(backup_ok) and os.path.getsize(backup_ok) > 0:
        pass
    else:
        report.write("Backup list is empty - is {} mounted?\n".format(backup))
        ret = 8
    if ret != 0:
        return ret
    else:
        pass


def compare_local_backup_with_s3_backup(s3_obj, config, list_dir, report):
    # Function to check intergrity of results between local backup and s3
    with open("{}/list.s3".format(list_dir), 'w') as f_list:
        s3_content_list = []
        while True:
            resp = s3_obj.connector.list_objects(Bucket=s3_obj.bucket_name)
            for obj in resp['Contents']:
                f_list.write("{}\n".format(obj['Key']))
                md5_returned = obj['ETag'].strip("\"")
                s3_content_list.append(Entry(obj['Key'], md5_returned))
            try:
                kwargs['ContinuationToken'] = resp['NextContinuationToken']
            except KeyError:
                break
    try:
        with open("{}/list.backup".format(list_dir)) as f:
            backup_content = f.readlines()
    except Exception as e:
        _logger.warning("{}/list.backup: file not found".format(list_dir))

    backup_content_list = []
    for content in backup_content:
        result_name = content.strip("\n")
        local_result_path = glob.glob(os.path.join(config.BACKUP, "*", result_name))
        local_result_md5 = ("{}.md5".format(local_result_path[0]))
        with open(local_result_md5) as k:
            md5_local = k.readline().split(" ")[0]
        backup_content_list.append(Entry(result_name, md5_local))

    # Call the two list to find out the difference.
    sorted_s3_content = sorted(s3_content_list, key=lambda k: k.name)
    sorted_backup_content = sorted(
        backup_content_list, key=lambda k: k.name)
    len_s3_content = len(sorted_s3_content)
    len_backup_content = len(sorted_backup_content)
    i, j = 0, 0
    while (i < len_s3_content) and (j < len_backup_content):
        if sorted_s3_content[i] == sorted_backup_content[j]:
            i += 1
            j += 1
        elif sorted_s3_content[i].name == sorted_backup_content[j].name:
            # the md5s are different even though the names are the same
            _logger.warning("Md5 check failed for: {}\n".format(
                sorted_s3_content[i].name))
            report.write("Md5 check failed for: {}\n".format(
                sorted_s3_content[i].name))
            i += 1
            j += 1
        elif sorted_s3_content[i].name < sorted_backup_content[j].name:
            report.write("{}: present in s3 but not in local backup\n".format(
                sorted_s3_content[i].name))
            i += 1
        elif sorted_s3_content[i].name > sorted_backup_content[j].name:
            report.write("{}: present in local backup but not in s3\n".format(
                sorted_backup_content[j].name))
            j += 1

    if i == len_s3_content and j < len_backup_content:
        for i in sorted_backup_content[j:len_backup_content]:
            report.write(
                "{}: present in local backup but not in s3\n".format(i.name))
    elif i < len_s3_content and j == len_backup_content:
        for i in sorted_s3_content[i:len_s3_content]:
            report.write(
                "{}: present in s3 but not in local backup\n".format(i.name))


def report_primary_backup_s3(list_dir, report):
    # Function to compare archive, backup and s3
    try:
        with open("{}/list.archive".format(list_dir)) as f:
            primary_list = set(f.readlines())
    except Exception as e:
        _logger.warning("{}/list.archive: file not found".format(list_dir))
    try:
        with open("{}/list.backup".format(list_dir)) as f:
            backup_list = set(f.readlines())
    except Exception as e:
        _logger.warning("{}/list.backup: file not found".format(list_dir))
    try:
        with open("{}/list.s3".format(list_dir)) as f:
            s3_list = set(f.readlines())
    except Exception as e:
        _logger.warning("{}/list.s3: file not found".format(list_dir))

    only_p = primary_list.difference(backup_list, s3_list)
    for i in only_p:
        report.write("{}: only in archive\n".format(i.strip('\n')))
        _logger.info("{}: only in archive\n".format(i.strip('\n')))

    only_b = backup_list.difference(primary_list, s3_list)
    for j in only_b:
        report.write("{}: only in backup\n".format(j.strip('\n')))
        _logger.info("{}: only in backup\n".format(j.strip('\n')))

    only_s3 = s3_list.difference(primary_list, backup_list)
    for k in only_s3:
        report.write("{}: only in s3\n".format(k.strip('\n')))
        _logger.info("{}: only in s3\n".format(k.strip('\n')))


def main(parsed):
    if not parsed.cfg_name:
        print("{}: ERROR: No config file specified; set CONFIG env variable or"
                " use --config <file> on the command line".format(_NAME_),
                file=sys.stderr)
        return 2

    try:
        config = PbenchConfig(parsed.cfg_name)
    except BadConfig as e:
        print("{}: {}".format(_NAME_, e), file=sys.stderr)
        return 1

    global _logger
    _logger = get_pbench_logger(_NAME_, config)

    # call the s3config class
    s3_obj = S3Config(config)

    _logger.info('start-{}'.format(config.timestamp()))

    archive = config.ARCHIVE
    if not os.path.isdir(archive):
        _logger.error(
            'The ARCHIVE directory does not resolve to a directory, {}'.format(archive))
        os._exit(1)

    # add a BACKUP field to the config object
    config.BACKUP = config.conf.get("pbench-server", "pbench-backup-dir")
    backup = config.BACKUP
    if len(backup) == 0:
        _logger.error(
            'Unspecified backup directory, no pbench-backup-dir config in pbench-server section')
        os._exit(1)

    if not os.path.isdir(backup):
        _logger.error('Specified backup directory, {}, does not resolve {} to a directory'.format(
            backup, os.path.realpath(backup)))
        os._exit(1)

    prog = os.path.basename(sys.argv[0])
    with tempfile.TemporaryDirectory() as list_dir:
        # Check the data integrity in Archive.
        checkmd5(config.ARCHIVE, list_dir, "archive")

        # Check the data integrity in Backup.
        checkmd5(config.BACKUP, list_dir, "backup")

        report = "{}/report".format(list_dir)
        with open(report, 'a') as reportf:
            # create a report for failed md5 results from archive and backup
            sts = report_failed_md5(list_dir, archive, backup, reportf)

            # Compare local backup with s3 backup.
            compare_local_backup_with_s3_backup(s3_obj, config, list_dir, reportf)

            if sts == 0:
                # Make report of results only present in archive, backup and s3.
                report_primary_backup_s3(list_dir, reportf)

        with open(report, 'r+') as f:
            content = f.read()
            f.seek(0, 0)
            f.write("{}.{}({})\n".format(prog, config.TS, config.PBENCH_ENV))
            f.write(content)

        es, idx_prefix = init_report_template(config, _logger)
        # Call report-status
        report_status(es, _logger, config.LOGSDIR,
                    idx_prefix, _NAME_, config.TS, "status", report)

    _logger.info('end-{}'.format(config.timestamp()))
    return sts


if __name__ == '__main__':
    parser = ArgumentParser("""Usage: pbench-verify-backup""")
    parser.set_defaults(cfg_name = os.environ.get("CONFIG"))
    parser.set_defaults(tmpdir = os.environ.get("TMPDIR"))
    parsed = parser.parse_args()

    status = main(parsed)
    sys.exit(status)
