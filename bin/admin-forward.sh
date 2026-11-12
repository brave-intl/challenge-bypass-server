#!/usr/bin/env bash
# Forward a local port to the challenge-bypass ECS task, for cbp-manage.
#
#   AWS_PROFILE=<profile> CLUSTER=<cluster> SERVICE=<service> \
#     bin/admin-forward.sh [local-port]
#
# Looks up the service's current running task on every run, so it keeps
# working after a deploy replaces the task. Logs in first if the SSO
# session has expired.
set -euo pipefail

: "${AWS_PROFILE:?set AWS_PROFILE}" "${CLUSTER:?set CLUSTER}" "${SERVICE:?set SERVICE}"
local_port=${1:-2418}

aws sts get-caller-identity >/dev/null 2>&1 || aws sso login

task=$(aws ecs list-tasks --cluster "$CLUSTER" --service-name "$SERVICE" \
	--desired-status RUNNING --query 'taskArns[0]' --output text)
if [ "$task" = None ] || [ -z "$task" ]; then
	echo "no running task for $SERVICE in $CLUSTER" >&2
	exit 1
fi
read -r image runtime < <(aws ecs describe-tasks --cluster "$CLUSTER" --tasks "$task" \
	--query 'tasks[0].containers[0].[image,runtimeId]' --output text)

echo "task ${task##*/} image $image"
echo "forwarding localhost:$local_port -> $SERVICE:2416"
exec aws ssm start-session \
	--target "ecs:${CLUSTER}_${task##*/}_${runtime}" \
	--document-name AWS-StartPortForwardingSession \
	--parameters "{\"portNumber\":[\"2416\"],\"localPortNumber\":[\"$local_port\"]}"
