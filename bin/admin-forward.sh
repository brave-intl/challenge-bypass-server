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

tasks=$(aws ecs list-tasks --cluster "$CLUSTER" --service-name "$SERVICE" \
	--desired-status RUNNING --query 'taskArns' --output text)
if [ "$tasks" = None ] || [ -z "$tasks" ]; then
	echo "no running task for $SERVICE in $CLUSTER" >&2
	exit 1
fi
# During a deploy the list includes tasks that have not started, which SSM
# cannot reach. Pick the newest running task, and in it the container whose
# exec agent is running, since sidecars come first in the container list.
# shellcheck disable=SC2086
read -r task image runtime < <(aws ecs describe-tasks --cluster "$CLUSTER" --tasks $tasks \
	--query 'sort_by(tasks[?lastStatus==`RUNNING`], &startedAt)[-1].[taskArn, containers[?managedAgents[?lastStatus==`RUNNING`]].image | [0], containers[?managedAgents[?lastStatus==`RUNNING`]].runtimeId | [0]]' \
	--output text)
if [ "$task" = None ] || [ "$runtime" = None ]; then
	echo "no task for $SERVICE is reachable yet; try again in a minute" >&2
	exit 1
fi

echo "task ${task##*/} image $image"
echo "forwarding localhost:$local_port -> $SERVICE:2416"
exec aws ssm start-session \
	--target "ecs:${CLUSTER}_${task##*/}_${runtime}" \
	--document-name AWS-StartPortForwardingSession \
	--parameters "{\"portNumber\":[\"2416\"],\"localPortNumber\":[\"$local_port\"]}"
