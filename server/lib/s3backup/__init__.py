"""
This module provides convenience functions that interface to lower-level services, provided by the boto3 module.
"""
import boto3
import os
import sys
import glob
import base64
import hashlib
import shutil
import time
import configtools
from datetime import datetime
from configparser import ConfigParser

from enum import Enum

class Status(Enum):
    SUCCESS = 0
    FAIL = 1
    ETAG_FAILURE = 2

class Entry(object):
    """
    An Entry object consists of a name (of an S3 object) and the MD5 value of that object. It is used to create an object with the name and MD5 value, so that it can be compared with other similar objects.
    """
    def __init__(self, name, md5):
        self.name = name
        self.md5 = md5

    def __eq__(self, other):
        return self.name == other.name and self.md5 == other.md5


def calculate_multipart_etag(source_path, chunk_size):
    md5s = []

    with open(source_path,'rb') as fp:
        while True:
            data = fp.read(chunk_size)
            if not data:
                break
            md5s.append(hashlib.md5(data))

    if len(md5s) > 1:
        digests = b"".join(m.digest() for m in md5s)
        new_md5 = hashlib.md5(digests)
        new_etag = '%s-%s' % (new_md5.hexdigest(),len(md5s))
    else:
        new_etag = ''

    return new_etag


class S3Connector(object):
    def __init__(self, config):
        self.endpoint_url = config.get('pbench-server-backup', 'endpoint_url')
        self.bucket_name = config.get('pbench-server-backup', 'bucket_name')
        self.access_key_id = config.get('pbench-server-backup', 'access_key_id')
        self.secret_access_key = config.get('pbench-server-backup', 'secret_access_key')
        self.s3client = boto3.client('s3',
                                        aws_access_key_id='{}'.format(
                                            access_key_id),
                                        aws_secret_access_key='{}'.format(
                                            secret_access_key),
                                        endpoint_url='{}'.format(endpoint_url))

    # XXX - need actual arguments here, not **kwargs
    def list_objects(self, **kwargs):
        return self.s3client.list_objects_v2(**kwargs)

    def head_bucket(self, Bucket=None):
        return self.s3client.head_bucket(Bucket)

    def get_object(self, Bucket=None, Key=None):
        return self.s3client.get_object(Bucket=Bucket, Key=Key)

    # XXX - arguments are wrong
    def put_object(self, Bucket=None, Key=None)
        return self.s3client.put_object(Stream?, MD5, Bucket=Bucket, Key=Key)

    # XXX - arguments are wrong
    def upload_fileobj(self, Stream??=None,  Bucket=None, Key=None, Config=None, ExtraArgs=None):
        return self.s3client.upload_fileobj(???)

    def delete_object(self, Bucket=None, Key=None):
        return self.s3client.delete_object(Bucket=Bucket, Key=Key)

class MockS3Connector(object):
    """
    The mock object is used for unit testing. It provides a "connector"
    to the backend service that is implemented using the local
    filesystem, rather than dispatching to the real S3 backend
    service.
    """

    def __init__(self, access_key_id, secret_access_key, endpoint_url, bucket_name):
        self.GB = 1024 ** 3
        self.path = endpoint_url
        self.bucket_name = bucket_name


    def list_objects(self, **kwargs):
        ob_dict = {}
        bucketpath = os.path.join(self.path, kwargs['Bucket'])
        result_list = glob.glob(os.path.join(bucketpath, "*/*.tar.xz"))
        result_list.sort()
        # we pretend that objects in the SPECIAL_BUCKET are large objects.
        if kwargs['Bucket'] == "SPECIAL_BUCKET":
            if 'ContinuationToken' in kwargs.keys():
                resp = self.create_ob_dict_for_list_objects(ob_dict,
                                                      bucketpath,
                                                      result_list[2:])
                return resp
            else:
                resp = self.create_ob_dict_for_list_objects(ob_dict,
                                                      bucketpath,
                                                      result_list[:2])
                resp['NextContinuationToken'] = 'yes'
                return resp
        else:
            resp = self.create_ob_dict_for_list_objects(ob_dict,
                                                   bucketpath,
                                                   result_list[:])
            return resp


    def put_object(self, Body=None, ContentMD5=None,  Bucket=None, Key=None):
        md5_hex_value = hashlib.md5(Body.read()).hexdigest()
        md5_base64_value = (base64.b64encode(
                        bytes.fromhex(md5_hex_value))).decode()
        if md5_base64_value == ContentMD5:
            test_controller = Key.split("/")[0]
            try:
                os.mkdir("{}/{}/{}".format(self.path,
                                           self.bucket_name, test_controller))
            except FileExistsError:
                # directory already exists, ignore
                pass
            with open('{}/{}/{}'.format(self.path, self.bucket_name, Key), 'wb') as f:
                f.write(Body.read())
            return Status.SUCCESS
        return Status.FAIL

    def upload_fileobj(self, read_content=None, Bucket=None, Key=None, Config=None, ExtraArgs=None):
        test_controller = Key.split("/")[0]
        try:
            os.mkdir("{}/{}/{}".format(self.path,
                                        self.bucket_name, test_controller))
        except FileExistsError:
            # directory already exists, ignore
            pass
        with open('{}/{}/{}'.format(self.path, self.bucket_name, Key), 'wb') as f:
            f.write(read_content.read())


    def head_bucket(self, Bucket=None):
        if os.path.exists(os.path.join(self.path, Bucket)):
            ob_dict = {}
            ob_dict['ResponseMetadata'] = {'HTTPStatusCode': 200}
            return ob_dict
        else:
            raise Exception("Bucket: {} doesn't exist".format(
                os.path.join(self.path, Bucket)))

    def get_object(self, Bucket=None, Key=None):
        ob_dict = {}
        result_path = os.path.join(self.path, Bucket, Key)
        with open(result_path, 'rb') as f:
            data = f.read()
            md5 = hashlib.md5(data).hexdigest()
        ob_dict['ResponseMetadata'] = {'HTTPStatusCode': 200}
        ob_dict['ETag'] = '"{}"'.format(md5)
        return ob_dict

    def create_ob_dict_for_list_objects(self, ob_dict, bucketpath, result_list):
        result_name_list = []
        for i in result_list:
            with open(i, 'rb') as f:
                data = f.read()
                md5 = hashlib.md5(data).hexdigest()
            result_name_list.append({'ETag': '"{}"'.format(md5),
                                     'Key': os.path.relpath(i, start=bucketpath)})
        ob_dict['Contents'] = result_name_list
        ob_dict['ResponseMetadata'] = {'HTTPStatusCode': 400}
        return ob_dict

    def getsize(self, tar):
        if '6.12' in tar:
            return 6442450944  # equivalent to 6 GB
        else:
            return os.path.getsize(tar)

    def upload_object(self, tar, s3_resultname, archive_md5_hex_value, bucket_name, logger, Status):
        tb_size = self.getsize(tar)
        if tb_size > (5 * self.GB):
            pass
        else:
            with open(tar, "rb") as data:
                md5_hex_value = hashlib.md5(data.read()).hexdigest()
                if md5_hex_value == archive_md5_hex_value:
                    test_controller = s3_resultname.split("/")[0]
                    try:
                        os.mkdir("{}/{}/{}".format(self.path,
                                                self.bucket_name, test_controller))
                    except FileExistsError:
                        # directory already exists, ignore
                        pass
                    with open('{}/{}/{}'.format(self.path, self.bucket_name, s3_resultname), 'wb') as f:
                        f.write(data.read())
        return Status.SUCCESS


class S3Config(object):
    def __init__(self, config, logger):
        try:
            debug_unittest = config.get('pbench-server', 'debug_unittest')
        except Exception as e:
            debug_unittest = False
        else:
            debug_unittest = bool(debug_unittest)

        self.GB = 1024 ** 3
        self.MB = 1024 ** 2
        self.chunk_size = 256 * self.MB
        self.multipart_threshold = 5 * self.GB
        self.logger = logger
        if debug_unittest:
            self.connector = MockS3Connector(config)
        else:
            self.connector = S3Connector(config)

    def getsize(self, tar):
        return os.path.getsize(tar)

    # pass through to the corresponding connector methods
    def get_tarball_header(self,  Bucket=None, Key=None):
        return self.connector.get_object(Bucket=Bucket, Key=Key)

    def put_tarball(self, Body=None, ContentMD5=None, Bucket=None, Key=None):
        # all the decisions about how to put the object are going to be in here
        md5_base64_value = (base64.b64encode(bytes.fromhex(archive_md5_hex_value))).decode()
        tb_size = self.getsize(tar)
        if tb_size > (5 * self.GB):
            multi_upload_config = TransferConfig(
                multipart_threshold=self.multipart_threshold, multipart_chunksize=self.chunk_size)
            # calculate multi etag value
            local_multipart_etag = calculate_multipart_etag(tar, self.chunk_size)
            try:
                with open(tar, "rb") as f:
                    try:
                        self.connector.upload_fileobj(f,
                                                        Bucket=bucket_name,
                                                        Key=s3_resultname,
                                                        Config = multi_upload_config,
           `                                            ExtraArgs = {'Metadata': { 'ETAG-MD5': local_multipart_etag, 'MD5SUM': archive_md5_hex_value}})
                    except ClientError as e:
                        self.logger.error(
                        "Multi-upload to s3 failed, client error: {}".format(e)
                        )
                        return Status.FAIL
                    else:
                        # compare the multi etag value uploaded in metadata
                        # field with s3 etag for data integrity.
                        try:
                            obj = self.connector.get_object(Bucket='{}'.format(bucket_name), Key='{}'.format(s3_resultname))
                        except Exception:
                            self.logger.exception("get_object failed: {}".format(s3_resultname))
                            return Status.FAIL
                        else:
                            s3_multipart_etag = obj['ETag'].strip("\"")
                            if s3_multipart_etag == local_multipart_etag:
                                self.logger.info("Multi-upload to s3 succeeded: {key}".format(key=s3_resultname))
                                return Status.SUCCESS
                            else:
                                # delete object from s3 and move to specific
                                # state directory for retry
                                self.connector.delete_object(Bucket='{}'.format(bucket_name), Key='{}'.format(s3_resultname))
                                self.logger.error("Multi-upload to s3 failed: {key},etag doesn't matched so moving it to ETAG_FAILURE for inspection".format(key=s3_resultname))
                                return Status.ETAG_FAILURE
            except Exception:
                # could not read tarball
                self.logger.exception(
                    "Failed to open tarball {tarball}".format(tarball=tar))
                return Status.FAIL
        else:
            try:
                with open(tar, 'rb') as data:
                    try:
                        self.connector.put_object(
                            Bucket=bucket_name, Key=s3_resultname, Body=data, ContentMD5=md5_base64_value)
                    except ConnectionClosedError:
                        # This is a transient failure and will be retried at
                        # the next invocation of the backups.
                        self,logger.error(
                            "Upload to s3 failed, connection was reset while transferring {key}".format(key=s3_resultname))
                        return Status.FAIL
                    except Exception:
                        # What ever the reason is for this failure, the
                        # operation will be retried the next time backups
                        # are run.
                        self.logger.exception(
                            "Upload to S3 failed while transferring {key}".format(key=s3_resultname))
                        return Status.FAIL
                    else:
                        self.logger.info(
                            "Upload to s3 succeeded: {key}".format(key=s3_resultname))
                        return Status.SUCCESS
            except Exception:
                # could not read tarball
                self.logger.exception(
                    "Failed to open tarball {tarball}".format(tarball=tar))
                return Status.FAIL

    # pass through to the corresponding connectir
    def head_bucket(Bucket=None):
        return self.connector.head_bucket(Bucket=Bucket)

    def list_objects(self, **kwargs):
        return self.connector.list_objects(**kwargs)
