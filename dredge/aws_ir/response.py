from __future__ import annotations

from typing import Optional, List

from .. import DredgeConfig
from .services import AwsServiceRegistry
from .models import OperationResult


class AwsIRResponse:
    """
    High-level incident *response* actions.

    These are orchestration methods that can call multiple AWS APIs
    and multiple low-level helpers under the hood.
    """

    def __init__(self, services: AwsServiceRegistry, config: DredgeConfig) -> None:
        self._services = services
        self._config = config

    # --------------------
    # IAM: Access Keys
    # --------------------

    def disable_access_key(self, user_name: str, access_key_id: str) -> OperationResult:
        """
        Set the given access key to Inactive.
        """
        result = OperationResult(
            operation="disable_access_key",
            target=f"user={user_name},access_key_id={access_key_id}",
            success=True,
        )

        if self._config.dry_run:
            result.details["dry_run"] = True
            return result

        iam = self._services.iam
        try:
            iam.update_access_key(
                UserName=user_name,
                AccessKeyId=access_key_id,
                Status="Inactive",
            )
            result.details["status"] = "Access key disabled"
        except Exception as exc:  # you might want to narrow this
            result.add_error(str(exc))

        return result

    def delete_access_key(self, user_name: str, access_key_id: str) -> OperationResult:
        """
        Permanently delete the given access key.
        """
        result = OperationResult(
            operation="delete_access_key",
            target=f"user={user_name},access_key_id={access_key_id}",
            success=True,
        )

        if self._config.dry_run:
            result.details["dry_run"] = True
            return result

        iam = self._services.iam
        try:
            iam.delete_access_key(UserName=user_name, AccessKeyId=access_key_id)
            result.details["status"] = "Access key deleted"
        except Exception as exc:
            result.add_error(str(exc))

        return result

    # --------------------
    # IAM: Users
    # --------------------

    def disable_user(self, user_name: str) -> OperationResult:
        """
        Disable a user by:
          - Deactivating all access keys
          - Removing from all groups
          - Deleting login profile
          - Detaching managed policies
          - Deleting inline policies
        """
        result = OperationResult(
            operation="disable_user",
            target=f"user={user_name}",
            success=True,
        )

        if self._config.dry_run:
            result.details["dry_run"] = True
            return result

        iam = self._services.iam

        try:
            # 1) Disable all access keys
            keys_resp = iam.list_access_keys(UserName=user_name)
            key_ids = [k["AccessKeyId"] for k in keys_resp.get("AccessKeyMetadata", [])]
            for key_id in key_ids:
                try:
                    iam.update_access_key(
                        UserName=user_name,
                        AccessKeyId=key_id,
                        Status="Inactive",
                    )
                except Exception as exc:
                    result.add_error(f"Failed to disable key {key_id}: {exc}")

            result.details["access_keys_disabled"] = key_ids

            # 2) Remove from groups
            groups_resp = iam.list_groups_for_user(UserName=user_name)
            group_names = [g["GroupName"] for g in groups_resp.get("Groups", [])]
            for group_name in group_names:
                try:
                    iam.remove_user_from_group(
                        GroupName=group_name,
                        UserName=user_name,
                    )
                except Exception as exc:
                    result.add_error(f"Failed to remove from group {group_name}: {exc}")

            result.details["groups_removed"] = group_names

            # 3) Delete login profile (if exists)
            try:
                iam.delete_login_profile(UserName=user_name)
                result.details["login_profile_deleted"] = True
            except iam.exceptions.NoSuchEntityException:
                result.details["login_profile_deleted"] = False
            except Exception as exc:
                result.add_error(f"Failed to delete login profile: {exc}")

            # 4) Detach managed policies
            attached_resp = iam.list_attached_user_policies(UserName=user_name)
            attached_arns = [
                p["PolicyArn"] for p in attached_resp.get("AttachedPolicies", [])
            ]
            for arn in attached_arns:
                try:
                    iam.detach_user_policy(UserName=user_name, PolicyArn=arn)
                except Exception as exc:
                    result.add_error(f"Failed to detach policy {arn}: {exc}")

            result.details["managed_policies_detached"] = attached_arns

            # 5) Delete inline policies
            inline_resp = iam.list_user_policies(UserName=user_name)
            inline_names = inline_resp.get("PolicyNames", [])
            for policy_name in inline_names:
                try:
                    iam.delete_user_policy(UserName=user_name, PolicyName=policy_name)
                except Exception as exc:
                    result.add_error(f"Failed to delete inline policy {policy_name}: {exc}")

            result.details["inline_policies_deleted"] = inline_names

        except Exception as exc:
            result.add_error(f"Fatal error disabling user: {exc}")

        return result

    # --------------------
    # IAM: Roles
    # --------------------

    def disable_role(self, role_name: str) -> OperationResult:
        """
        Disable a role by:
          - Detaching all managed policies
          - Deleting all inline policies
          - Clearing trust relationship (set to empty)
        """
        result = OperationResult(
            operation="disable_role",
            target=f"role={role_name}",
            success=True,
        )

        if self._config.dry_run:
            result.details["dry_run"] = True
            return result

        iam = self._services.iam

        try:
            # Detach managed policies
            attached_resp = iam.list_attached_role_policies(RoleName=role_name)
            attached_arns = [
                p["PolicyArn"] for p in attached_resp.get("AttachedPolicies", [])
            ]
            for arn in attached_arns:
                try:
                    iam.detach_role_policy(RoleName=role_name, PolicyArn=arn)
                except Exception as exc:
                    result.add_error(f"Failed to detach policy {arn}: {exc}")
            result.details["managed_policies_detached"] = attached_arns

            # Delete inline policies
            inline_resp = iam.list_role_policies(RoleName=role_name)
            inline_names = inline_resp.get("PolicyNames", [])
            for policy_name in inline_names:
                try:
                    iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name)
                except Exception as exc:
                    result.add_error(f"Failed to delete inline policy {policy_name}: {exc}")
            result.details["inline_policies_deleted"] = inline_names

            # Clear trust relationship
            iam.update_assume_role_policy(
                RoleName=role_name,
                PolicyDocument='{"Version":"2012-10-17","Statement":[]}',
            )
            result.details["trust_relationship_cleared"] = True

        except Exception as exc:
            result.add_error(f"Fatal error disabling role {role_name}: {exc}")

        return result

    # --------------------
    # S3: Block public access
    # --------------------

    def block_s3_public_access(
        self,
        account_id: str,
        *,
        block_public_acls: bool = True,
        ignore_public_acls: bool = True,
        block_public_policy: bool = True,
        restrict_public_buckets: bool = True,
    ) -> OperationResult:
        """
        Enable S3 Block Public Access at the account level.

        Uses s3control.PutPublicAccessBlock.
        """
        result = OperationResult(
            operation="block_s3_public_access",
            target=f"account={account_id}",
            success=True,
        )

        if self._config.dry_run:
            result.details["dry_run"] = True
            return result

        s3control = self._services.s3control

        try:
            s3control.put_public_access_block(
                AccountId=account_id,
                PublicAccessBlockConfiguration={
                    "BlockPublicAcls": block_public_acls,
                    "IgnorePublicAcls": ignore_public_acls,
                    "BlockPublicPolicy": block_public_policy,
                    "RestrictPublicBuckets": restrict_public_buckets,
                },
            )
            result.details["status"] = "S3 public access blocked at account level"
        except Exception as exc:
            result.add_error(str(exc))

        return result

    # --------------------
    # EC2: Isolate instances
    # --------------------

    def isolate_ec2_instances(
        self,
        instance_ids: list[str],
        *,
        vpc_id: Optional[str] = None,
        sg_name: str = "dredge-forensic-isolation",
        description: str = "Dredge forensic isolation group (no inbound/outbound)",
    ) -> OperationResult:
        """
        Isolate one or more EC2 instances by:
          - Creating (or reusing) a security group with no ingress/egress
          - Assigning that SG to the instances (replacing existing groups)
        """
        result = OperationResult(
            operation="isolate_ec2_instances",
            target=",".join(instance_ids),
            success=True,
        )

        if self._config.dry_run:
            result.details["dry_run"] = True
            return result

        ec2 = self._services.ec2

        try:
            if not vpc_id:
                # Infer VPC from first instance
                desc = ec2.describe_instances(InstanceIds=[instance_ids[0]])
                reservations = desc.get("Reservations", [])
                if not reservations or not reservations[0]["Instances"]:
                    raise RuntimeError("Unable to infer VPC ID from instance")
                vpc_id = reservations[0]["Instances"][0]["VpcId"]

            # Try to find existing SG
            sg_id = self._find_or_create_isolation_sg(
                ec2=ec2,
                vpc_id=vpc_id,
                sg_name=sg_name,
                description=description,
            )
            result.details["isolation_security_group_id"] = sg_id

            # Replace SGs on each instance
            for instance_id in instance_ids:
                try:
                    ec2.modify_instance_attribute(
                        InstanceId=instance_id,
                        Groups=[sg_id],
                    )
                except Exception as exc:
                    result.add_error(f"Failed to isolate {instance_id}: {exc}")

        except Exception as exc:
            result.add_error(f"Fatal error isolating instances: {exc}")

        return result

    # ---- internal helpers ----

    @staticmethod
    def _find_or_create_isolation_sg(ec2, vpc_id: str, sg_name: str, description: str) -> str:
        # Try to find
        resp = ec2.describe_security_groups(
            Filters=[
                {"Name": "group-name", "Values": [sg_name]},
                {"Name": "vpc-id", "Values": [vpc_id]},
            ]
        )
        groups = resp.get("SecurityGroups", [])
        if groups:
            return groups[0]["GroupId"]

        # Create new SG with no rules
        create_resp = ec2.create_security_group(
            GroupName=sg_name,
            Description=description,
            VpcId=vpc_id,
        )
        sg_id = create_resp["GroupId"]

        # Ensure no ingress/egress rules (API might create default egress)
        try:
            ec2.revoke_security_group_egress(
                GroupId=sg_id,
                IpPermissions=[
                    {
                        "IpProtocol": "-1",
                        "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                    }
                ],
            )
        except Exception:
            # If there were no default rules, this might fail. We can ignore.
            pass

        return sg_id

    # --------------------
    # IAM: Delete user (uses disable_user first)
    # --------------------

    def delete_user(self, user_name: str) -> OperationResult:
        """
        Fully delete an IAM user in a safe-ish way:

          1) Call disable_user(user_name) to:
             - deactivate all access keys
             - remove from groups
             - delete login profile
             - detach managed policies
             - delete inline policies
          2) Delete the IAM user object itself.

        NOTE: This is destructive. Prefer disable_user for containment
        and only delete when you're sure.
        """
        # First, reuse disable_user
        disable_result = self.disable_user(user_name)

        result = OperationResult(
            operation="delete_user",
            target=f"user={user_name}",
            success=disable_result.success,
            details=dict(disable_result.details),
            errors=list(disable_result.errors),
        )

        if self._config.dry_run:
            result.details["dry_run"] = True
            return result

        iam = self._services.iam

        # If disable_user already had a fatal error, we still *attempt*
        # deletion but keep the errors.
        try:
            iam.delete_user(UserName=user_name)
            result.details["user_deleted"] = True
        except Exception as exc:
            result.add_error(f"Failed to delete user {user_name}: {exc}")

        return result

    # --------------------
    # S3: Bucket / object level block
    # --------------------

    def block_s3_bucket_public_access(self, bucket_name: str) -> OperationResult:
        """
        Make a bucket 'private' in an IR context by:

          - Setting S3 Block Public Access at bucket level
          - Setting ACL to 'private'
          - Deleting bucket policy (if present)

        This roughly corresponds to your 'Make a bucket private' action.
        """
        result = OperationResult(
            operation="block_s3_bucket_public_access",
            target=f"bucket={bucket_name}",
            success=True,
        )

        if self._config.dry_run:
            result.details["dry_run"] = True
            return result

        s3 = self._services.s3

        try:
            # 1) Block Public Access (bucket-level)
            s3.put_public_access_block(
                Bucket=bucket_name,
                PublicAccessBlockConfiguration={
                    "BlockPublicAcls": True,
                    "IgnorePublicAcls": True,
                    "BlockPublicPolicy": True,
                    "RestrictPublicBuckets": True,
                },
            )
            result.details["public_access_blocked"] = True
        except Exception as exc:
            result.add_error(f"Failed to set bucket PublicAccessBlock: {exc}")

        try:
            # 2) ACL -> private
            s3.put_bucket_acl(Bucket=bucket_name, ACL="private")
            result.details["acl_set_private"] = True
        except Exception as exc:
            result.add_error(f"Failed to set bucket ACL to private: {exc}")

        try:
            # 3) Delete bucket policy (if any)
            s3.delete_bucket_policy(Bucket=bucket_name)
            result.details["bucket_policy_deleted"] = True
        except s3.exceptions.from_code("NoSuchBucketPolicy"):  # may or may not exist
            result.details["bucket_policy_deleted"] = False
        except Exception as exc:
            # Some SDKs don't expose NoSuchBucketPolicy; we just record error.
            result.add_error(f"Failed to delete bucket policy: {exc}")

        return result

    def block_s3_object_public_access(self, bucket_name: str, key: str) -> OperationResult:
        """
        Make a single object 'private' by:

          - Setting ACL to 'private'

        This corresponds to your 'Make an object private' action.
        """
        result = OperationResult(
            operation="block_s3_object_public_access",
            target=f"bucket={bucket_name},key={key}",
            success=True,
        )

        if self._config.dry_run:
            result.details["dry_run"] = True
            return result

        s3 = self._services.s3

        try:
            s3.put_object_acl(
                Bucket=bucket_name,
                Key=key,
                ACL="private",
            )
            result.details["acl_set_private"] = True
        except Exception as exc:
            result.add_error(f"Failed to set object ACL to private: {exc}")

        return result