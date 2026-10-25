# Secure access handoff for an S3/KMS restore drill

This guide gives Codex temporary, least-privilege access for a credentialed Litestream restore drill without storing credentials in this repository. The recommended method is AWS IAM Identity Center (SSO), which supplies short-lived credentials through an AWS CLI profile outside the repository.

## Access model

Use a dedicated role or IAM Identity Center permission set for the drill. Do not provide an IAM user's long-lived access key.

The drill identity should have:

- read-only access to the existing production Litestream prefix;
- read/write/delete access only to a new isolated drill prefix;
- decrypt access to the production SSE-KMS key;
- encrypt/data-key/decrypt access to that key for the isolated write-and-restore test;
- read-only access to bucket encryption, versioning, Object Lock and public-access settings;
- a session duration of one hour where organizational policy permits.

It must not have permission to modify bucket policy, public access, versioning, lifecycle, KMS policy, production replica objects, IAM resources, or the production database.

## 1. Choose the two prefixes

Record these values outside the repository:

```text
AWS account ID:       <ACCOUNT_ID>
AWS region:           <REGION>
S3 bucket:            <BUCKET>
Production prefix:    <PRODUCTION_PREFIX>
Drill prefix:         licd/drills/<UTC-DATE>-<RANDOM-ID>
KMS key ARN:          <KMS_KEY_ARN>
```

The drill prefix must not overlap the production prefix. Do not run a second Litestream writer against the production replica path.

## 2. Create a least-privilege permission policy

Replace every angle-bracket placeholder. Prefixes must not start with `/` and should not end with `*` in the substituted value.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "InspectBucketProtection",
      "Effect": "Allow",
      "Action": [
        "s3:GetBucketLocation",
        "s3:GetEncryptionConfiguration",
        "s3:GetBucketVersioning",
        "s3:GetBucketPublicAccessBlock",
        "s3:GetBucketPolicyStatus",
        "s3:GetBucketObjectLockConfiguration"
      ],
      "Resource": "arn:aws:s3:::<BUCKET>"
    },
    {
      "Sid": "ListOnlyApprovedPrefixes",
      "Effect": "Allow",
      "Action": "s3:ListBucket",
      "Resource": "arn:aws:s3:::<BUCKET>",
      "Condition": {
        "StringLike": {
          "s3:prefix": [
            "<PRODUCTION_PREFIX>",
            "<PRODUCTION_PREFIX>/*",
            "<DRILL_PREFIX>",
            "<DRILL_PREFIX>/*"
          ]
        }
      }
    },
    {
      "Sid": "ReadProductionReplica",
      "Effect": "Allow",
      "Action": [
        "s3:GetObject",
        "s3:GetObjectVersion"
      ],
      "Resource": "arn:aws:s3:::<BUCKET>/<PRODUCTION_PREFIX>/*"
    },
    {
      "Sid": "ManageOnlyIsolatedDrillObjects",
      "Effect": "Allow",
      "Action": [
        "s3:GetObject",
        "s3:PutObject",
        "s3:DeleteObject",
        "s3:AbortMultipartUpload",
        "s3:ListMultipartUploadParts"
      ],
      "Resource": "arn:aws:s3:::<BUCKET>/<DRILL_PREFIX>/*"
    },
    {
      "Sid": "DescribeDrillKMSKey",
      "Effect": "Allow",
      "Action": "kms:DescribeKey",
      "Resource": "<KMS_KEY_ARN>"
    },
    {
      "Sid": "UseKMSOnlyThroughS3",
      "Effect": "Allow",
      "Action": [
        "kms:Decrypt",
        "kms:GenerateDataKey"
      ],
      "Resource": "<KMS_KEY_ARN>",
      "Condition": {
        "StringEquals": {
          "kms:CallerAccount": "<ACCOUNT_ID>",
          "kms:ViaService": "s3.<REGION>.amazonaws.com"
        }
      }
    }
  ]
}
```

If the drill will restore production only and will not test a fresh encrypted write, omit `ManageOnlyIsolatedDrillObjects`, remove the drill prefix from `ListOnlyApprovedPrefixes`, and omit `kms:GenerateDataKey`.

The KMS key policy must also permit this role, or must delegate authorization to IAM policies in the account. Cross-account buckets/keys require authorization from both accounts. Do not grant KMS administrative actions such as `PutKeyPolicy`, `CreateGrant`, `ScheduleKeyDeletion`, or wildcard `kms:*`.

## 3. Configure short-lived local authentication

Install AWS CLI v2 using the official installer, then configure IAM Identity Center:

```powershell
aws configure sso --profile licd-restore-drill
aws sso login --profile licd-restore-drill
```

Use `--use-device-code` with `aws configure sso` only when the normal browser/PKCE flow cannot be used. The profile is stored under `%USERPROFILE%\.aws\config`, and the short-lived SSO token cache is under `%USERPROFILE%\.aws\sso\cache`; neither location is inside this repository.

If the drill runs on an EC2 instance, ECS task or another AWS workload, a dedicated workload role is preferable and no local profile is needed.

Do not:

- run `aws configure` with long-lived access keys;
- paste access keys, session tokens, SSE-C keys or SSO tokens into chat;
- put credentials in YAML, `.env` files, PowerShell history, command arguments, GitHub Actions variables, or any path under this repository;
- grant `AmazonS3FullAccess`, `AdministratorAccess`, wildcard bucket access, or access to unrelated KMS keys.

## 4. Create an out-of-repository handoff file

Create `C:\ProgramData\licd-drill\access.yaml` or another protected path outside the repository:

```yaml
aws_profile: licd-restore-drill
aws_account_id: "<ACCOUNT_ID>"
region: "<REGION>"
bucket: "<BUCKET>"
production_prefix: "<PRODUCTION_PREFIX>"
drill_prefix: "<DRILL_PREFIX>"
kms_key_arn: "<KMS_KEY_ARN>"
```

This file contains identifiers, not credentials, but should still be readable only by the operator account and Administrators/System. Do not place it in `configs/`, `docs/`, the workspace root, or any other Git-controlled directory.

## 5. Verify the session locally

These commands do not reveal credentials:

```powershell
aws sts get-caller-identity --profile licd-restore-drill
aws s3api head-bucket --bucket <BUCKET> --profile licd-restore-drill
aws kms describe-key --key-id <KMS_KEY_ARN> --profile licd-restore-drill
```

Confirm that the returned principal is the dedicated drill role—not an administrator role—and that the account ID matches the expected account.

## 6. Hand access to Codex

Reply in this task with only:

```text
AWS profile: licd-restore-drill
Handoff file: C:\ProgramData\licd-drill\access.yaml
Isolated drill-prefix writes and cleanup are authorized: yes
```

Do not send secret values. Codex will then:

1. verify the caller identity and effective read/write boundaries;
2. inspect bucket encryption, versioning, public-access and Object Lock status;
3. download checksum-verified Litestream tooling if necessary;
4. dry-run and restore the latest production recovery point to a protected local temporary directory;
5. select and dry-run a retained point-in-time boundary, then restore and verify it;
6. replicate a synthetic database only to the isolated drill prefix using SSE-KMS, restore it and confirm the object encryption metadata;
7. run SQLite integrity, foreign-key and application audit checks;
8. report measured RPO/RTO and exact evidence without logging licence data or credentials;
9. delete only the isolated drill-prefix objects and protected local files created by the drill, after resolving and checking their exact paths.

Production replica objects will remain read-only throughout the drill.

For the built-in automated read/restore drill, supply the short-lived profile to the service process through its protected environment, set `recovery_drill.mode: credentialed`, and run:

```powershell
$env:AWS_PROFILE = "licd-restore-drill"
licctl --config C:\ProgramData\licd\config.yaml recovery-drill run --mode credentialed --wait
```

When `licd` runs as a Windows Service or systemd unit, setting `AWS_PROFILE` in the operator shell does not change the service environment. Configure the short-lived profile/session for the service identity through the approved protected service environment, restart it, run the drill, and remove that configuration afterward. The built-in drill reads the production Litestream prefix and configured archive and does not need the isolated-prefix write permissions unless the separate synthetic upload test described above is also being performed. See `recovery-drills.md` for report interpretation.

## 7. Revoke access after the drill

After the report is complete:

1. remove the role assignment or temporary permission set;
2. remove the dedicated role/policy if it was created only for this drill;
3. run `aws sso logout` if ending all locally cached AWS SSO sessions is acceptable;
4. remove the out-of-repository handoff file;
5. review CloudTrail for the drill role and confirm activity was limited to the approved prefixes and KMS key.

Do not delete the production replica or its object versions as part of access revocation.

## References

- [AWS CLI IAM Identity Center configuration](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-sso.html)
- [AWS S3 API permission mappings](https://docs.aws.amazon.com/AmazonS3/latest/userguide/using-with-s3-policy-actions.html)
- [AWS KMS permission reference](https://docs.aws.amazon.com/kms/latest/developerguide/kms-api-permissions-reference.html)
- [Litestream S3 and restrictive IAM guidance](https://litestream.io/guides/s3/)
