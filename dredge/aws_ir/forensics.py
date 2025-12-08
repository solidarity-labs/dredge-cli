from __future__ import annotations

from typing import Dict, List

from .. import DredgeConfig
from .services import AwsServiceRegistry
from .models import OperationResult

class AwsIRForensics:
    """
    Forensics-focused actions (snapshots, evidence collection, etc.).

    Example:
        dredge.aws_ir.forensics.get_ebs_snapshot(volume_id="vol-123", description="IR case X")
    """

    def __init__(self, services: AwsServiceRegistry, config: DredgeConfig) -> None:
        self._services = services
        self._config = config

    def get_ebs_snapshot(
        self,
        volume_id: str,
        *,
        description: str = "Dredge forensic snapshot",
    ) -> OperationResult:
        """
        Create a snapshot of the specified EBS volume.

        (Name matches your intent: `dredge.aws_ir.forensics.get_ebs_snapshoot`
         but with `snapshot` spelled correctly.)
        """
        result = OperationResult(
            operation="get_ebs_snapshot",
            target=f"volume={volume_id}",
            success=True,
        )

        if self._config.dry_run:
            result.details["dry_run"] = True
            return result

        ec2 = self._services.ec2

        try:
            resp = ec2.create_snapshot(
                VolumeId=volume_id,
                Description=description,
            )
            snapshot_id = resp["SnapshotId"]
            result.details["snapshot_id"] = snapshot_id
        except Exception as exc:
            result.add_error(str(exc))

        return result

    def snapshot_instance_volumes(
        self,
        instance_id: str,
        *,
        include_root: bool = True,
        description_prefix: str = "Dredge forensic snapshot",
    ) -> OperationResult:
        """
        Snapshot all (or non-root) EBS volumes attached to an instance.

        This is a higher-level helper built on top of per-volume snapshotting.

        Rough mapping to your "Get Forensic Image from EC2 instance volume",
        but generalized to all volumes for a given instance.
        """
        result = OperationResult(
            operation="snapshot_instance_volumes",
            target=f"instance={instance_id}",
            success=True,
        )

        if self._config.dry_run:
            result.details["dry_run"] = True
            return result

        ec2 = self._services.ec2
        snapshot_ids: Dict[str, str] = {}  # volume_id -> snapshot_id

        try:
            desc = ec2.describe_instances(InstanceIds=[instance_id])
            reservations = desc.get("Reservations", [])
            if not reservations or not reservations[0]["Instances"]:
                raise RuntimeError(f"No instance found: {instance_id}")

            instance = reservations[0]["Instances"][0]
            block_devices = instance.get("BlockDeviceMappings", [])

            # Identify root device name (e.g. /dev/xvda) if we need to filter
            root_device_name = instance.get("RootDeviceName")

            for mapping in block_devices:
                device_name = mapping.get("DeviceName")
                ebs = mapping.get("Ebs")
                if not ebs:
                    continue

                volume_id = ebs["VolumeId"]

                if not include_root and device_name == root_device_name:
                    continue

                try:
                    desc_text = f"{description_prefix} for {instance_id} ({device_name})"
                    snap_resp = ec2.create_snapshot(
                        VolumeId=volume_id,
                        Description=desc_text,
                    )
                    snapshot_id = snap_resp["SnapshotId"]
                    snapshot_ids[volume_id] = snapshot_id
                except Exception as exc:
                    result.add_error(
                        f"Failed to snapshot volume {volume_id} on {device_name}: {exc}"
                    )

            result.details["snapshots"] = snapshot_ids

        except Exception as exc:
            result.add_error(f"Fatal error snapshotting instance volumes: {exc}")

        return result

    def get_lambda_environment(
        self,
        function_name: str,
        *,
        qualifier: str | None = None,
    ) -> OperationResult:
        """
        Fetch environment variables for a Lambda function.

        This corresponds to your 'Get Lambda env vars' IR helper.

        NOTE: This returns env vars in cleartext in the result.details,
        so handle logs and outputs carefully.
        """
        result = OperationResult(
            operation="get_lambda_environment",
            target=f"function={function_name},qualifier={qualifier or 'LATEST'}",
            success=True,
        )

        if self._config.dry_run:
            # For dry-run, we do *not* call AWS but just mark as dry-run
            result.details["dry_run"] = True
            return result

        lambda_client = self._services.lambda_

        try:
            kwargs = {"FunctionName": function_name}
            if qualifier:
                kwargs["Qualifier"] = qualifier

            resp = lambda_client.get_function_configuration(**kwargs)
            env = resp.get("Environment", {}).get("Variables", {})

            result.details["environment_variables"] = env
        except Exception as exc:
            result.add_error(f"Failed to fetch lambda environment: {exc}")

        return result
