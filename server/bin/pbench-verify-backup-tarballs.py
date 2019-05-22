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

class Status(Enum):
    SUCCESS = 10
    FAIL = 20

class BackupObject(object):
    def __init__(self, name, dirname):
        self.name = name
        self.dirname = dirname
        self.list_name = "list.{}".format(self.name)
        self.description = self.name

def sanity_check(s3_obj, logger):
    # make sure the S3 bucket exists
    try:
        s3_obj.connector.head_bucket(Bucket='{}'.format(s3_obj.bucket_name))
    except Exception:
        logger.exception(
            "Bucket: {} does not exist or you have no access\n".format(s3_obj.bucket_name))
        s3_obj = None

    return s3_obj

def checkmd5(target_dir, tmpdir, backup_obj, logger):
    # Function to check integrity of results in a local (archive or local
    # backup) directory
    if not os.path.isdir(target_dir):
        logger.error('Bad {}: {}'.format(indicator, target_dir))
        return Status.FAIL

    tarlist = glob.iglob(os.path.join(target_dir, "*", "*.tar.xz"))
    indicator_file = os.path.join(tmpdir, backup_obj.list_name)
    indicator_file_ok = os.path.join(tmpdir, "{}.ok".
                                     format(backup_obj.list_name))
    indicator_file_fail = os.path.join(tmpdir, "{}.fail".
                                       format(backup_obj.list_name))
    try:
        with open(indicator_file, 'w') as f_list,\
             open(indicator_file_ok, 'w') as f_ok,\
             open(indicator_file_fail, 'w') as f_fail:
             try:
                 for tar in tarlist:
                     result_name = os.path.basename(tar)
                     controller = os.path.basename(
                         os.path.dirname(tar))
                     md5 = ("{}.md5".format(tar))
                     f_list.write("{}\n".format(os.path.join(controller, result_name)))
                     try:
                         with open(md5) as f:
                             md5_value = f.readline().split(" ")[0]
                     except (OSError, IOError) as e:
                         # Could not read file
                         logger.error(
                             "Could not read file {}, {}\n".format(md5, e))
                         continue

                     md5_returned = md5sum(tar)
                     if md5_value == md5_returned:
                         f_ok.write("{}: {}\n".format(os.path.join(controller, result_name), "OK"))
                     else:
                         f_fail.write("{}: {}\n".format(os.path.join(controller, result_name), "FAILED"))
                 return Status.SUCCESS
             except Exception as e:
                 logger.error("{}\n".format(e))
                 return Status.FAIL
    except (OSError, IOError) as e:
        # Could not open file for writing
        logger.error(
            "Could not open one of the temp files for writing {}, {}\n".
            format((indicator_file, indicator_file_ok, indicator_file_fail), e))
        return Status.FAIL

def report_failed_md5(backup_obj, tmpdir, report, logger):
    fail_f = os.path.join(tmpdir, "{}.fail",format(backup_obj.list_name))
    if os.path.exists(fail_f) and os.path.getsize(fail_) > 0:
        try:
            with open(fail_f) as f:
                failed_list = f.read()
        except (OSError, IOError) as e:
            # Could not read file
            logger.error(
                "Could not read file {}, {}\n".format(fail_f, e))
        else:
            report.write(
                "ERROR: in {}: the calculated MD5 of the following entries "
                "failed to match the stored MD5:\n {}".format(backup_obj.name, failed_list_a))

def compare_with_s3_backup(s3_config_obj, backup_obj, tmpdir, report, logger):

    if s3_config_obj is None:
        return Status.FAIL

    # Function to check intergrity of results between local backup and s3
    list_s3 = os.path.join(tmpdir, "list.s3")
    try:
        with open(list_s3, 'w') as f_list:
            try:
                s3_content_list = []
                while True:
                    resp = s3_config_obj.connector.list_objects(s3_config_obj.bucket_name)
                    for obj in resp['Contents']:
                        f_list.write("{}\n".format(obj['Key']))
                        md5_returned = obj['ETag'].strip("\"")
                        s3_content_list.append(Entry(obj['Key'], md5_returned))
                    try:
                        kwargs['ContinuationToken'] = resp['NextContinuationToken']
                    except KeyError:
                        break
            except Exception as e:
                logger.error("{}\n".format(e))
                return Status.FAIL
    except (OSError, IOError) as e:
        logger.error(
            "Could not read file {}, {}\n".format(list_s3, e))
        return Status.FAIL

    list_backup = os.path.join(tmpdir, backup_obj.list_name)
    try:
        with open(list_backup) as f:
            backup_content = f.readlines()
    except (OSError, IOError) as e:
        logger.error(
            "Could not read file {}, {}\n".format(list_backup, e))
        return Status.FAIL
    else:
        backup_content_list = []
        for content in backup_content:
            result_name = content.strip("\n")
            local_result_path = os.path.join(backup_obj.dirname, result_name)
            local_result_md5 = "{}.md5".format(local_result_path)
            try:
                with open(local_result_md5) as k:
                    md5_local = k.readline().split(" ")[0]
            except (OSError, IOError) as e:
                logger.error(
                    "Could not read file {}, {}\n".format(local_result_md5, e))
                continue
            else:
                backup_content_list.append(Entry(result_name, md5_local))

    # Compare the two lists and report the differences.
    sorted_s3_content = sorted(s3_content_list, key=lambda k: k.name)
    sorted_backup_content = sorted(backup_content_list, key=lambda k: k.name)
    len_s3_content = len(sorted_s3_content)
    len_backup_content = len(sorted_backup_content)
    i, j = 0, 0
    # logger.info("S3 list")
    # for s in sorted_s3_content:
    #     logger.info("{}".format(s.name))
    # logger.info("{} list".format(backup_obj.name))
    # for s in sorted_backup_content:
    #     logger.info("{}".format(s.name))
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
            report_text = "{}: present in s3 but not in {}\n".format(
                sorted_s3_content[i].name, backup_obj.description)
            report.write(report_text)
            i += 1
        elif sorted_s3_content[i].name > sorted_backup_content[j].name:
            report_text = "{}: present in {} but not in s3\n".format(
                sorted_backup_content[j].name, backup_obj.description)
            report.write(report_text)
            j += 1

    if i == len_s3_content and j < len_backup_content:
        for i in sorted_backup_content[j:len_backup_content]:
            report_text = "{}: present in {}  but not in s3\n".format(
                i.name, backup_obj.description)
            report.write(report_text)
    elif i < len_s3_content and j == len_backup_content:
        for i in sorted_s3_content[i:len_s3_content]:
            report_text = "{}: present in s3 but not in {}\n".format(
                i.name, backup_obj.description)
            report.write(report_text)
    return Status.SUCCESS


def report_primary_backup_s3(archive_obj, backup_obj, s3_backup_obj, tmpdir, report, logger):
    # Function to compare archive, backup and s3
    aname = os.path.join(tmpdir, archive_obj.list_name)
    try:
        with open(aname) as f:
            primary_list = set(f.readlines())
    except Exception as e:
        logger.exception("error reading {}, {}\n".format(aname, e))
        return Status.FAIL

    bname = os.path.join(tmpdir, backup_obj.list_name)
    try:
        with open(bname) as f:
            backup_list = set(f.readlines())
    except Exception as e:
       logger.exception("error reading {}, {}\n".format(bname, e))
       return Status.FAIL

    sname = os.path.join(tmpdir, s3_backup_obj.list_name)
    try:
        with open(sname) as f:
            s3_list = set(f.readlines())
    except Exception as e:
        logger.exception("error reading {}, {}\n".format(sname, e))
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

    logger = get_pbench_logger(_NAME_, config)

    archive = config.ARCHIVE
    if not os.path.isdir(archive):
        logger.error('The ARCHIVE directory does not resolve to a directory, {}\n'.
                      format(archive))
        return 1

    # add a BACKUP field to the config object
    config.BACKUP = backup = config.conf.get("pbench-server", "pbench-backup-dir")
    if len(backup) == 0:
        logger.error("Unspecified backup directory, no pbench-backup-dir "\
                      "config in pbench-server section\n")
        return 1

    if not os.path.isdir(backup):
        logger.error('Specified backup directory, {}, does not resolve {} to a directory\n'.
                      format(backup, os.path.realpath(backup)))
        return 1

    # call the s3config class
    s3_config_obj = S3Config(config)
    s3_config_obj = sanity_check(s3_config_obj, logger)

    # logger.info(s3_config_obj.connector.path)
    # logger.info(s3_config_obj.connector.bucket_name)
    logger.info('start-{}'.format(config.TS))

    prog = os.path.basename(sys.argv[0])

    sts = 0
    # N.B. tmpdir is the pathname of the temp directory.
    with tempfile.TemporaryDirectory() as tmpdir:

        archive_obj = BackupObject("archive", config.ARCHIVE)
        local_backup_obj = BackupObject("backup", config.BACKUP)
        s3_backup_obj = BackupObject("s3", s3_config_obj)

        # Check the data integrity in Archive.
        md5_result_archive = checkmd5(config.ARCHIVE, tmpdir, archive_obj, logger)
        # logger.info("md5_result_archive: {}".format(md5_result_archive))

        # Check the data integrity in Backup.
        md5_result_backup = checkmd5(config.BACKUP, tmpdir, local_backup_obj, logger)
        # logger.info("md5_result_backup: {}".format(md5_result_backup))

        with tempfile.NamedTemporaryFile(mode='w+t', dir=tmpdir) as report:
            report.write("{}.{}({})\n".format(prog, config.TS, config.PBENCH_ENV))

            if s3_config_obj is None:
                report.write('S3 backup service is inaccessible.')

            if md5_result_archive == Status.FAIL:
                # create a report for failed md5 results from archive
                report_failed_md5(archive_obj, tmpdir, report, logger)
                sts += 1

            if md5_result_backup == Status.FAIL:
                # create a report for failed md5 results from archive
                report_failed_md5(local_backup_obj, tmpdir, report, logger)
                sts += 1

            if md5_result_archive == Status.SUCCESS:
                # Compare archive with s3 backup.
                compare_result = compare_with_s3_backup(s3_config_obj,
                                                        archive_obj,
                                                        tmpdir, report, logger)
            elif md5_result_backup == Status.SUCCESS:
                # Compare local backup with s3 backup.
                compare_result = compare_with_s3_backup(s3_config_obj,
                                                        local_backup_obj,
                                                        tmpdir, report, logger)
            else:
                # bail for now - we should keep track of the md5
                # failures, and compare the one with the fewest such
                # failures against s3, but make sure that we skip the
                # failures. TBD.
                compare_result = Status.FAIL
                sts += 100

            if compare_result == Status.FAIL:
                sts += 1

            diff_status = report_primary_backup_s3(archive_obj,
                                                   local_backup_obj,
                                                   s3_backup_obj,
                                                   tmpdir, report, logger)
            if diff_status == Status.FAIL:
                sts += 1

            # Send the report out.

            # Rewind to the beginning.
            report.seek(0)
            es, idx_prefix = init_report_template(config, logger)
            report_status(es, logger, config.LOGSDIR,
                          idx_prefix, _NAME_, config.TS, "status", report.name)

    logger.info('end-{}'.format(config.timestamp()))

    return sts


if __name__ == '__main__':
    status = main()
    sys.exit(status)
