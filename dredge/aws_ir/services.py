from __future__ import annotations

import boto3


class AwsServiceRegistry:
    """
    Central place to create and share boto3 clients/resources.
    """

    def __init__(self, session: boto3.Session) -> None:
        self._session = session

        # Lazily initialized clients
        self._iam = None
        self._ec2 = None
        self._s3control = None
        self._s3 = None
        self._lambda = None
        self._cloudtrail = None   # <-- add this

    @property
    def iam(self):
        if self._iam is None:
            self._iam = self._session.client("iam")
        return self._iam

    @property
    def ec2(self):
        if self._ec2 is None:
            self._ec2 = self._session.client("ec2")
        return self._ec2

    @property
    def s3control(self):
        if self._s3control is None:
            self._s3control = self._session.client("s3control")
        return self._s3control

    @property
    def s3(self):
        if self._s3 is None:
            self._s3 = self._session.client("s3")
        return self._s3

    @property
    def lambda_(self):
        if self._lambda is None:
            self._lambda = self._session.client("lambda")
        return self._lambda

    @property
    def cloudtrail(self):
        if self._cloudtrail is None:
            self._cloudtrail = self._session.client("cloudtrail")
        return self._cloudtrail
