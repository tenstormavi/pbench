#!/usr/bin/env python3
# -*- mode: python -*-

import os
import sys
import glob
import hashlib
import shutil
import tempfile
from enum import Enum
from argparse import ArgumentParser
from s3backup import S3Config, Entry
from pbench import init_report_template, report_status, _rename_tb_link, \
    PbenchConfig, BadConfig, get_es, get_pbench_logger, md5sum

_NAME_    = "pbench-verify-backup-tarballs"

# Global logger for the module, setup in main()
_logger = None


class Status(Enum):
    SUCCESS = 10
    FAIL = 20

def checkmd5(target_dir, reference_dir, indicator):
    # Function to check integrity of results in a local (archive or local backup) directory
    if not os.path.isdir(target_dir):
        _logger.error('Bad {}: {}'.format(indicator, target_dir))
        return Status.FAIL

    tarlist = glob.iglob(os.path.join(target_dir, "*", "*.tar.xz"))
    indicator_file = os.path.join(
        reference_dir, "list.{}".format(indicator))
    indicator_file_ok = os.path.join(
        reference_dir, "list.{}.ok".format(indicator))
    indicator_file_fail = os.path.join(
        reference_dir, "list.{}.fail".format(indicator))
    try:
        with open(indicator_file, 'w') as f_list:
            try:
                with open(indicator_file_ok, 'w') as f_ok:
                    try:
                        with open(indicator_file_fail, 'w') as f_fail:
                            try:
                                for tar in tarlist:
                                    result_name = os.path.basename(tar)
                                    controller = os.path.basename(
                                        os.path.dirname(tar))
                                    md5 = ("{}.md5".format(tar))
                                    f_list.write("{}\n".format(
                                        os.path.join(controller, result_name)))

                                    try:
                                        with open(md5) as f:
                                            md5_value = f.readline().split(" ")[0]
                                    except (OSError, IOError) as e:
                                        # Could not read file
                                        _logger.error(
                                            "Could not read file {}, {}\n".format(md5, e))
                                        continue

                                    md5_returned = md5sum(tar)
                                    if md5_value == md5_returned:
                                        f_ok.write(
                                            "{}: {}\n".format(os.path.join(controller, result_name), "OK"))
                                    else:
                                        f_fail.write(
                                            "{}: {}\n".format(os.path.join(controller, result_name), "FAILED"))
                                return Status.SUCCESS
                            except Exception as e:
                                _logger.error("{}\n".format(e))
                                return Status.FAIL
                    except (OSError, IOError) as e:
                        # Could not read file
                        _logger.error(
                            "Could not read file {}, {}\n".format(indicator_file_fail, e))
                        return Status.FAIL
            except (OSError, IOError) as e:
                # Could not read file
                _logger.error(
                    "Could not read file {}, {}\n".format(indicator_file_ok, e))
                return Status.FAIL
    except (OSError, IOError) as e:
        # Could not read file
        _logger.error(
            "Could not read file {}, {}\n".format(indicator_file, e))
        return Status.FAIL


def report_failed_md5(reference_dir, report):
    archive_fail = os.path.join(reference_dir, 'list.archive.fail')
    if os.path.exists(archive_fail) and os.path.getsize(archive_fail) > 0:
        try:
            with open(archive_fail) as f:
                failed_list_a = f.read()
        except (OSError, IOError) as e:
            # Could not read file
            _logger.error(
                "Could not read file {}, {}\n".format(archive_fail, e))
        else:
            report.write(
                "In Archive: the calculated MD5 of the following entries failed to match the stored MD5:\n {}".format(failed_list_a))

    backup_fail = os.path.join(reference_dir, 'list.backup.fail')
    if os.path.exists(backup_fail) and os.path.getsize(backup_fail) > 0:
        try:
            with open(backup_fail) as f:
                failed_list_b = f.read()
        except (OSError, IOError) as e:
            # Could not read file
            _logger.error(
                "Could not read file {}, {}\n".format(backup_fail, e))
        else:
            report.write(
                "In Backup: the calculated MD5 of the following entries failed to match the stored MD5:\n {}".format(failed_list_b))


def compare_local_backup_with_s3_backup(config, reference_dir, report):
    # call the s3config class
    s3_obj = S3Config(config)

    # Function to check intergrity of results between local backup and s3
    list_s3 = os.path.join(reference_dir, "list.s3")
    try:
        with open(list_s3, 'w') as f_list:
            try:
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
            except Exception as e:
                _logger.error("{}\n".format(e))
                return Status.FAIL
    except (OSError, IOError) as e:
        _logger.error(
            "Could not read file {}, {}\n".format(list_s3, e))
        return Status.FAIL

    list_backup = os.path.join(reference_dir, "list.backup")
    try:
        with open(list_backup) as f:
            backup_content = f.readlines()
    except (OSError, IOError) as e:
        _logger.error(
            "Could not read file {}, {}\n".format(list_backup, e))
        return Status.FAIL
    else:
        backup_content_list = []
        for content in backup_content:
            result_name = content.strip("\n")
            local_result_path = os.path.join(config.BACKUP, result_name)
            local_result_md5 = "{}.md5".format(local_result_path)
            try:
                with open(local_result_md5) as k:
                    md5_local = k.readline().split(" ")[0]
            except (OSError, IOError) as e:
                _logger.error(
                    "Could not read file {}, {}\n".format(local_result_md5, e))
                continue
            else:
                backup_content_list.append(Entry(result_name, md5_local))

    # Compare the two lists to find out the differences.
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
            report_text = "Md5 check failed for: {}\n".format(
                sorted_s3_content[i].name)
            report.write(report_text)
            i += 1
            j += 1
        elif sorted_s3_content[i].name < sorted_backup_content[j].name:
            report_text = "{}: present in s3 but not in local backup\n".format(
                sorted_s3_content[i].name)
            report.write(report_text)
            i += 1
        elif sorted_s3_content[i].name > sorted_backup_content[j].name:
            report_text = "{}: present in local backup but not in s3\n".format(
                sorted_backup_content[j].name)
            report.write(report_text)
            j += 1

    if i == len_s3_content and j < len_backup_content:
        for i in sorted_backup_content[j:len_backup_content]:
            report_text = "{}: present in local backup but not in s3\n".format(
                i.name)
            report.write(report_text)
    elif i < len_s3_content and j == len_backup_content:
        for i in sorted_s3_content[i:len_s3_content]:
            report_text = "{}: present in s3 but not in local backup\n".format(
                i.name)
            report.write(report_text)
    return Status.SUCCESS


def report_primary_backup_s3(reference_dir, report):
    # Function to compare archive, backup and s3
    aname = os.path.join(reference_dir, "list.archive")
    try:
        with open(aname) as f:
            primary_list = set(f.readlines())
    except Exception as e:
        _logger.exception("error reading {}, {}\n".format(aname, e))
        return Status.FAIL

    bname = os.path.join(reference_dir, "list.backup")
    try:
        with open(bname) as f:
            backup_list = set(f.readlines())
    except Exception as e:
       _logger.exception("error reading {}, {}\n".format(bname, e))
       return Status.FAIL

    sname = os.path.join(reference_dir, "list.s3")
    try:
        with open(sname) as f:
            s3_list = set(f.readlines())
    except Exception as e:
        _logger.exception("error reading {}, {}\n".format(sname, e))
        return Status.FAIL

    only_p = primary_list.difference(backup_list, s3_list)
    for i in sorted(only_p):
        report.write("{}: only in archive\n".format(i.strip('\n')))

    only_b = backup_list.difference(primary_list, s3_list)
    for j in sorted(only_b):
        report.write("{}: only in backup\n".format(j.strip('\n')))

    only_s3 = s3_list.difference(primary_list, backup_list)
    for k in sorted(only_s3):
        report.write("{}: only in s3\n".format(k.strip('\n')))
    return Status.SUCCESS


def main():
    cfg_name = os.environ.get("CONFIG")
    if not cfg_name:
        print("{}: ERROR: No config file specified; set CONFIG env variable or"
                " use --config <file> on the command line".format(_NAME_),
                file=sys.stderr)
        return 2

    try:
        config = PbenchConfig(cfg_name)
    except BadConfig as e:
        print("{}: {}".format(_NAME_, e), file=sys.stderr)
        return 1

    global _logger
    _logger = get_pbench_logger(_NAME_, config)

    archive = config.ARCHIVE
    if not os.path.isdir(archive):
        _logger.error(
            'The ARCHIVE directory does not resolve to a directory, {}\n'.format(archive))
        return 1

    # add a BACKUP field to the config object
    config.BACKUP = backup = config.conf.get("pbench-server", "pbench-backup-dir")
    if len(backup) == 0:
        _logger.error(
            'Unspecified backup directory, no pbench-backup-dir config in pbench-server section\n')
        return 1

    if not os.path.isdir(backup):
        _logger.error('Specified backup directory, {}, does not resolve {} to a directory\n'.format(
            backup, os.path.realpath(backup)))
        return 1

    _logger.info('start-{}'.format(config.TS))

    prog = os.path.basename(sys.argv[0])
    with tempfile.TemporaryDirectory() as reference_dir:
        # Check the data integrity in Archive.
        md5_result_archive = checkmd5(config.ARCHIVE, reference_dir, "archive")

        # Check the data integrity in Backup.
        md5_result_backup = checkmd5(config.BACKUP, reference_dir, "backup")

        with tempfile.NamedTemporaryFile(mode='w+t', dir=reference_dir) as report:
            report.write("{}.{}({})\n".format(
                prog, config.TS, config.PBENCH_ENV))

            if md5_result_archive == Status.SUCCESS and md5_result_backup == Status.SUCCESS:
                # create a report for failed md5 results from archive and backup
                report_failed_md5(reference_dir, report)

            if md5_result_backup == Status.SUCCESS:
                # Compare local backup with s3 backup.
                compare_result = compare_local_backup_with_s3_backup(config, reference_dir, report)

            if md5_result_archive == Status.SUCCESS and md5_result_backup == Status.SUCCESS:
                if compare_result == Status.SUCCESS:
                    # Make report of results only present in archive, backup and s3.
                    sts = report_primary_backup_s3(reference_dir, report)

            report.seek(0)
            es, idx_prefix = init_report_template(config, _logger)
            # Call report-status
            report_status(es, _logger, config.LOGSDIR,
                        idx_prefix, _NAME_, config.TS, "status", report.name)

    _logger.info('end-{}'.format(config.timestamp()))
    return 0


if __name__ == '__main__':
    status = main()
    sys.exit(status)
