#!/usr/bin/env python3
# -*- mode: python -*-

import os
import sys
import glob
import base64
import hashlib
import shutil
import tempfile
import pathlib
from enum import Enum
from argparse import ArgumentParser

from pbench import init_report_template, report_status, _rename_tb_link, \
    PbenchConfig, BadConfig, get_es, get_pbench_logger, quarantine
from s3backup import S3Config

_NAME_ = "pbench-backup-tarballs"

# The link source and destination for this operation of this script.
_linksrc = "TO-BACKUP"

# Global logger for the module, setup in main()
_logger = None

class Status(Enum):
    SUCCESS = 10
    FAIL = 20


class Results(object):
    def __init__(self, ntotal=0, nbackup_success=0, nbackup_fail=0, ns3_success=0, ns3_fail=0, nquaran=0):
        self.ntotal = ntotal
        self.nbackup_success = nbackup_success
        self.nbackup_fail = nbackup_fail
        self.ns3_success = ns3_success
        self.ns3_fail = ns3_fail
        self.nquaran = nquaran


def sanity_check(s3_obj, config, logger):

    # make sure archive is present
    archive = config.ARCHIVE

    if not os.path.realpath(archive):
        logger.error(
            'The ARCHIVE directory {}, does not resolve to a real location'.format(archive))
        return 1

    if not os.path.isdir(archive):
        logger.error(
            'The ARCHIVE directory {}, does not resolve {} to a directory'.format(archive, os.path.realpath(archive)))
        return 1

    # make sure the local backup directory is present
    backup = config.BACKUP

    if len(backup) == 0:
        logger.error(
            'Unspecified backup directory, no pbench-backup-dir config in pbench-server section')
        return 1

    try:
        os.mkdir(backup)
    except FileExistsError:
        # directory already exists, verify it
        if not os.path.realpath(backup):
            logger.error(
                'The BACKUP directory {}, does not resolve to a real location'.format(backup))
            return 1

        if not os.path.isdir(backup):
            logger.error(
                'The BACKUP directory {}, does not resolve {} to a directory'.format(backup, os.path.realpath(backup)))
            return 1
    except Exception:
        logger.exception(
            "os.mkdir: Unable to create backup destination directory: {}\n".format(backup))
        return 1

    # make sure the quarantine directory is present
    qdir = config.QDIR

    if len(qdir) == 0:
        logger.error(
            'Unspecified quarantine directory, no pbench-quarantine-dir config in pbench-server section')
        return 1

    if not os.path.realpath(qdir):
        logger.error(
            'The QUARANTINE directory {}, does not resolve to a real location'.format(qdir))
        return 1

    if not os.path.isdir(qdir):
        logger.error(
            'The QUARANTINE directory {}, does not resolve {} to a directory'.format(qdir, os.path.realpath(qdir)))
        return 1

    # make sure the S3 bucket exists
    try:
        s3_obj.connector.head_bucket(Bucket='{}'.format(s3_obj.bucket_name))
    except Exception as e:
        logger.exception(
            "Bucket: {} does not exist or you have no access. {}\n".format(s3_obj.bucket_name, e))
        return 1


def backup_to_local(config, logger, controller_path, controller, tb, tar, resultname, archive_md5, archive_md5_hex_value):

    backup_controller_path = "{}/{}".format(config.BACKUP, controller)

    # make sure the controller is present in local backup directory
    try:
        os.mkdir(backup_controller_path)
    except FileExistsError:
        # directory already exists, ignore
        pass
    except Exception:
        logger.exception(
            "os.mkdir: Unable to create backup destination directory: {}\n".format(backup_controller_path))
        return Status.FAIL

    # Check if tarball exist in local backup
    backup_tar = os.path.join(backup_controller_path, resultname)
    if os.path.exists(backup_tar) and os.path.isfile(backup_tar):
        backup_md5 = (
            "{}/{}.md5".format(backup_controller_path, resultname))

        # check backup md5 file exist and it is a regular file
        if os.path.exists(backup_md5) and os.path.isfile(backup_md5):
            pass
        else:
            # backup md5 file does not exist or it is not a regular file
            logger.error(
                "{} does not exist or it is not a regular file\n".format(backup_md5))
            return Status.FAIL

        # read backup md5 file
        try:
            with open(backup_md5) as f:
                backup_md5_hex_value = f.readline().split(" ")[0]
        except (OSError, IOError) as e:
            # Could not read file
            logger.error(
                "Could not read file {}, {}\n".format(backup_md5, e))
            return Status.FAIL
        else:
            if archive_md5_hex_value == backup_md5_hex_value:
                # declare success
                logger.info(
                    "Already locally backed-up: {}\n".format(resultname))
                return Status.SUCCESS
            else:
                # md5 file of archive and backup does not match
                logger.error(
                    "{} already exists in backup but md5 sums of archive and backup disagree\n".format(resultname))
                return Status.FAIL
    else:
        md5_done = tar_done = False

        # copy the md5 file from archive to backup
        try:
            shutil.copy(archive_md5, backup_controller_path)
            md5_done = True
        except Exception:
            # couldn't copy md5 file
            logger.exception(
                "shutil.copy: Unable to copy {} from archive to backup: {}\n".format(archive_md5, backup_controller_path))

        # copy the tarball from archive to backup
        if md5_done:
            try:
                shutil.copy(tar, backup_controller_path)
                tar_done = True
            except Exception:
                # couldn't copy tarball
                logger.exception(
                    "shutil.copy: Unable to copy {} from archive to backup: {}\n".format(tar, backup_controller_path))

                # remove the copied md5 file from backup
                bmd5_file = "{}/{}.md5".format(
                    backup_controller_path, resultname)
                if os.path.exists(bmd5_file):
                    try:
                        os.remove(bmd5_file)
                    except Exception:
                        logger.exception("Unable to remove: {}".format(bmd5_file))

        if md5_done and tar_done:
            logger.info(
                "Locally Backed-up Sucessfully: {}\n".format(resultname))
            return Status.SUCCESS
        else:
            return Status.FAIL


def backup_to_s3(s3_obj, logger, controller_path, controller, tb, tar, resultname, archive_md5_hex_value):

    s3_resultname = "{}/{}".format(controller, resultname)

    # Check if the result already present in s3 or not
    try:
        obj = s3_obj.connector.get_object(Bucket='{}'.format(
            s3_obj.bucket_name), Key='{}'.format(s3_resultname))
        in_s3 = True
    except Exception:
        in_s3 = False

    if in_s3:
        # compare md5 which we already have so no need to recalculate
        s3_md5 = obj['ETag'].strip("\"")

        if archive_md5_hex_value == s3_md5:
            # declare success
            logger.info(
                "The tarball {} is already present in S3 bucket, with same md5\n".format(s3_resultname))
            return Status.SUCCESS
        else:
            logger.error(
                "The tarball {} is already present in S3 bucket, but with different MD5\n".format(s3_resultname))
            return Status.FAIL
    else:
        md5_base64_value = (base64.b64encode(
            bytes.fromhex(archive_md5_hex_value))).decode()
        try:
            with open(tar, 'rb') as data:
                try:
                    s3_obj.connector.put_object(
                        Bucket=s3_obj.bucket_name, Key=s3_resultname, Body=data, ContentMD5=md5_base64_value)
                except Exception as e:
                    logger.exception(
                        "Upload to s3 failed, Bad md5 for: {}, {}\n".format(s3_resultname, e))
                    return Status.FAIL
                else:
                    logger.info(
                        "Upload to s3 succeeded: {}\n".format(s3_resultname))
                    return Status.SUCCESS
        except (OSError, IOError) as e:
            # could not read tarball
            logger.error(
                "Failed to open tarball, {}\n".format(tar, e))
            return Status.FAIL


def backup_data(s3_obj, config, logger):
    qdir = config.QDIR

    tarlist = glob.iglob('{}/*/{}/*.tar.xz'.format(config.ARCHIVE, _linksrc))
    ntotal = nbackup_success = nbackup_fail = \
        ns3_success = ns3_fail = nquaran = 0

    for tb in sorted(tarlist):
        ntotal += 1
        # resolve the link
        tar = os.path.realpath(tb)

        # check tarball exist and it is a regular file
        if os.path.exists(tar) and os.path.isfile(tar):
            pass
        else:
            # tarball does not exist or it is not a regular file
            quarantine(qdir, logger, tb)
            nquaran += 1
            logger.error(
                "Quarantine: {}, {} does not exist or it is not a regular file\n".format(tb, tar))
            continue

        archive_md5 = ("{}.md5".format(tar))

        # check md5 file exist and it is a regular file
        if os.path.exists(archive_md5) and os.path.isfile(archive_md5):
            pass
        else:
            # md5 file does not exist or it is not a regular file
            quarantine(qdir, logger, tb)
            nquaran += 1
            logger.error(
                "Quarantine: {}, {} does not exist or it is not a regular file\n".format(tb, archive_md5))
            continue

        # read the md5sum from md5 file
        try:
            with open(archive_md5) as f:
                archive_md5_hex_value = f.readline().split(" ")[0]
        except (OSError, IOError) as e:
            # Could not read file.
            quarantine(qdir, logger, tb)
            nquaran += 1
            logger.error(
                "Quarantine: {}, Could not read {}, {}\n".format(tb, archive_md5, e))
            continue

        # match md5sum of the tarball to its md5 file
        try:
            with open(tar, 'rb') as f:
                adata = f.read()
                try:
                    archive_tar_hex_value = hashlib.md5(adata).hexdigest()
                except Exception as e:
                    quarantine(qdir, logger, tb)
                    nquaran += 1
                    logger.error(
                        "Quarantine: {}, Unable to calculate the hexadecimal md5 value for {}, {}\n".format(tb, tar, e))
                    continue
        except (OSError, IOError) as e:
            # Could not read file.
            quarantine(qdir, logger, tb)
            nquaran += 1
            logger.error(
                "Quarantine: {}, Could not read {}, {}\n".format(tb, tar, e))
            continue
        else:
            if archive_tar_hex_value == archive_md5_hex_value:
                pass
            else:
                quarantine(qdir, logger, tb)
                nquaran += 1
                logger.error(
                    "Quarantine: {}, md5sum of {} does not match with its md5 file {}\n".format(tb, tar, archive_md5))
                continue

        resultname = os.path.basename(tar)
        controller_path = os.path.dirname(tar)
        controller = os.path.basename(controller_path)
        backup_controller_path = "{}/{}".format(config.BACKUP, controller)

        # This function call will handle all the local backup related
        # operations and count the number of success and failure.
        local_backup_result = backup_to_local(
            config, logger, controller_path, controller, tb, tar, resultname, archive_md5, archive_md5_hex_value)

        if local_backup_result == Status.SUCCESS:
            nbackup_success  += 1
        elif local_backup_result == Status.FAIL:
            nbackup_fail += 1
        else:
            assert False, "Impossible situation, local_backup_result = {}".format(
                local_backup_result)

        # This function call will handle all the S3 bucket related
        # operations and count the number of success and failure.
        s3_backup_result = backup_to_s3(
            s3_obj, logger, controller_path, controller, tb, tar, resultname, archive_md5_hex_value)

        if s3_backup_result == Status.SUCCESS:
            ns3_success += 1
        elif s3_backup_result == Status.FAIL:
            ns3_fail += 1
        else:
            assert False, "Impossible situation, s3_backup_result = {}".format(
                s3_backup_result)

        if local_backup_result == Status.SUCCESS \
            and s3_backup_result == Status.SUCCESS:
            # moved to backed-up
            _rename_tb_link(tb, os.path.join(
                controller_path, "BACKED-UP"), logger)
        elif local_backup_result == Status.SUCCESS \
            and s3_backup_result == Status.FAIL:
            # move to backed-up-local
            _rename_tb_link(tb, os.path.join(
                controller_path, "BACKED-UP-LOCAL"), logger)
        elif local_backup_result == Status.FAIL \
            and s3_backup_result == Status.SUCCESS:
            # move to backed-up-S3
            _rename_tb_link(tb, os.path.join(
                controller_path, "BACKED-UP-S3"), logger)
        elif local_backup_result == Status.FAIL \
            and s3_backup_result == Status.FAIL:
            # move tp backed-up-failed
            _rename_tb_link(tb, os.path.join(
                controller_path, "BACKED-UP-FAILED"), logger)
        else:
            assert False, "Logic bomb: cannot happen: local_backup_result = \
                {}, s3_backup_result = {}".format(local_backup_result,                                           s3_backup_result)

    return Results(ntotal=ntotal,
                   nbackup_success=nbackup_success,
                   nbackup_fail=nbackup_fail,
                   ns3_success=ns3_success,
                   ns3_fail=ns3_fail,
                   nquaran=nquaran)


def main(parsed):
    ret_status = 0
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

    # call the S3Config class
    s3_obj = S3Config(config)

    _logger.info('start-{}'.format(config.timestamp()))

    # add a BACKUP field to the config object
    config.BACKUP = config.conf.get("pbench-server", "pbench-backup-dir")
    config.QDIR = config.get('pbench-server', 'pbench-quarantine-dir')

    sanity_check(s3_obj, config, _logger)

    prog = os.path.basename(sys.argv[0])

    # Initiate the backup
    counts = backup_data(s3_obj, config, _logger)

    result_string = ("Total processed: {}, "
                     "Locally backed-ed succesfully: {}, "
                     "Failed to locally backed-up: {}, "
                     "Uploaded to S3 succesfully: {}, "
                     "Failed to upload to S3: {}, Quarantine: {}"
                    .format(counts.ntotal,
                            counts.nbackup_success,
                            counts.nbackup_fail,
                            counts.ns3_success,
                            counts.ns3_fail,
                            counts.nquaran))

    _logger.info(result_string)

    # prepare and send report
    with tempfile.NamedTemporaryFile(mode='w+t', dir=config.TMP) as report:
        report.write("{}.{}({})\n{}\n".format(
            prog, config.timestamp(), config.PBENCH_ENV, result_string))
        report.seek(0)

        es, idx_prefix = init_report_template(config, _logger)
        # Call report-status
        report_status(es, _logger, config.LOGSDIR,
                      idx_prefix, _NAME_, config.timestamp(), "status", (pathlib.Path(report.name)))

    _logger.info('end-{}'.format(config.timestamp()))

    return ret_status


if __name__ == '__main__':
    parser = ArgumentParser("""Usage: pbench-backup""")
    parser.set_defaults(cfg_name=os.environ.get("CONFIG"))
    parser.set_defaults(tmpdir=os.environ.get("TMPDIR"))
    parsed = parser.parse_args()

    status = main(parsed)
    sys.exit(status)
