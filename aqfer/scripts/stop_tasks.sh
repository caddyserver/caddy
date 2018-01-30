#!/usr/bin/env bash
# set -e

aws ecs list-tasks --cluster $1 > /tmp/tasks
task_arns=$(cat /tmp/tasks | perl -pe 's|[\n\s]+|=|g' | sed -E 's/.*\[=="(.*)"==\].*/\1/')
for arn in $(echo $task_arns | tr "\",==\"" "\n"); do
  aws ecs stop-task --cluster $1 --task $arn
done
