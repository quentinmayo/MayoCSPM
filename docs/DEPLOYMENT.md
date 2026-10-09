# Deployment

Choose where data will live before installing. PostgreSQL is the supported durable
database. SQLite is for local development and tests; MySQL is not supported.
The initial schema is created on startup. There is no general upgrade migration
system yet: back up and rehearse restoration before changing an installed release.

## Docker Compose / Ubuntu VM

Install Docker Engine and Compose from the
[official Docker guide](https://docs.docker.com/engine/install/ubuntu/) and Python 3.
Clone the repository, inspect `scripts/setup.sh`, then run it. The script creates
private `.env`, builds locally, starts services, and waits for health checks.
It does not install Docker, change firewall rules, create AWS resources, or expose
the database. Re-running preserves configuration and data.

Default bindings are `127.0.0.1:8010` for the app and no published worker/database
ports. For a remote VM:

```sh
ssh -L 8010:127.0.0.1:8010 your-user@your-host
```

Open `http://localhost:8010`. For direct HTTPS access, configure your own maintained
reverse proxy, DNS and TLS, set `PUBLIC_URL=https://your-host.example`, and recreate
the app. Browser mutations require exactly that origin. Never publish `.env`, a
Docker socket, operator AWS profiles, or PostgreSQL credentials.

Compose caps the app at 384 MiB/0.5 CPU, worker at 512 MiB/0.5 CPU, and PostgreSQL
at 384 MiB/0.5 CPU. These are runtime limits, not build-time or filesystem quotas.
Deploy one app and one worker. The worker owns AWS access; the controller never
needs it. Use the [AWS guide](AWS.md) when you are ready to collect real metadata.

Base images use Docker's official-library ECR Public mirror to avoid anonymous
Docker Hub pull limits. This is an installation-time image fetch, separate from
cloud inventory collection. You can set `POSTGRES_IMAGE` to an approved registry
mirror/digest and build with `--build-arg PYTHON_IMAGE=your-approved-python-image`.
No customer ECR repositories or layers are downloaded by the collector.

## External PostgreSQL

Create a dedicated database/user, configure TLS with a trusted CA, and add
`EXTERNAL_DATABASE_URL=postgresql+psycopg://…?sslmode=verify-full` to private `.env`.
If a private CA is required, mount its public certificate and set the PostgreSQL
SSL root-certificate option. Passwords containing URL-reserved characters must be
URL-encoded. Use the overlay (Compose 2.24.4+):

```sh
docker compose -f compose.yaml -f deploy/compose.external-db.yaml up -d --build --wait
```

The local database service is put into an unused profile; the controller waits on
its external database via connection attempts. The overlay syntax is validated
locally, but a remote TLS database integration has not yet been exercised.

## Unraid / external disk

Use the Compose plugin or a dedicated Ubuntu VM. Select a new persistent path
in `MAYOCSPM_DATA_PATH`, create its parent directory, and apply
`deploy/compose.unraid.yaml`. PostgreSQL initializes its own data directory.
Do not reuse another application's database directory.

```sh
docker compose -f compose.yaml -f deploy/compose.unraid.yaml up -d --build --wait
```

Choose a pool/dataset that supports the required database semantics and backups.
Check that the external drive is mounted before startup; otherwise a missing
mount can silently place files on the root disk. Set host filesystem quotas and
monitor free space. Actual Unraid installation for this new project remains to
be validated; CheckMayo's deployment results do not validate MayoCSPM.

## AWS

A small EC2 Ubuntu host running Compose is the simplest initial AWS path. Use an
instance profile restricted to assuming your collector roles, TLS ingress through
your approved reverse proxy/load balancer, and a dedicated PostgreSQL database
or persistent volume. Permit only your required ingress and administrative path.
Set metadata access for containers deliberately; the default Compose worker
disables EC2 metadata until configured.

ECS can run separate app and worker tasks, with an AWS task role only on the worker,
and an external PostgreSQL database. Use explicit task CPU/memory limits, encrypted
log storage and a resource budget. The local Compose file is not an ECS task
definition. No EC2/ECS/EKS infrastructure is automatically provisioned or claimed
tested by this release. See [AWS task IAM roles](https://docs.aws.amazon.com/AmazonECS/latest/developerguide/task-iam-roles.html).

## Kubernetes

Treat app and worker as separate single-replica Deployments, each running the same
image with different commands. Use a dedicated external PostgreSQL database,
Kubernetes Secrets, resource requests/limits, read-only root filesystems, UID
10001, dropped capabilities and no privilege escalation. Give workload identity
only to the worker and restrict its egress to the required APIs/database. Use
TLS ingress and an exact `PUBLIC_URL`. A production chart and actual Kubernetes
deployment test are planned, not included as a verified deployment path.

## Backup and restore

Create a restricted private backup directory and redirect `pg_dump` there, never
into a repository or public web directory. Back up `ENCRYPTION_KEY` separately.

```sh
umask 077
docker compose exec -T db pg_dump -U mayocspm -d mayocspm -Fc > /private/backup/path/mayocspm.dump
```

Restore into a **new isolated database** first using `pg_restore`, the same engine
revision, and the original encryption key. Verify authentication, membership,
resource counts and token decryption without printing tokens. Choose backup
retention and validate quota/free space; this preview does not automate backups
or promise a tested upgrade/restore contract. `docker compose down` preserves
volumes; `down -v` permanently removes this stack's named volumes.
