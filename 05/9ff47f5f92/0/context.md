# Session Context

## User Prompts

### Prompt 1

My dba reports that the database is struggling with some locks on the tables host, layer_stat, subscription, transactionid. Please investigate queries on 

[@dao](file:///Users/dtavares/dev/OpenCue/rust/crates/scheduler/src/dao)

 and 

[@postgres](file:///Users/dtavares/dev/OpenCue/cuebot/src/main/java/com/imageworks/spcue/dao/postgres)

 for scheduler and cuebot and come up with some theories on what might be the issue.

### Prompt 2

[Request interrupted by user for tool use]

### Prompt 3

Talking with my DBA, all points to Theory 1. And since cuebot was already running for a long time without issues, I suppose scheduler is the culprit. Help me to brainstorm a solution.

### Prompt 4

I partially agree with the assesment. Bug what about the verify_subscription trigger 

[@V1__Initial_schema.sql#L2907:2924](file:///Users/dtavares/dev/OpenCue/cuebot/src/main/resources/conf/ddl/postgres/migrations/V1__Initial_schema.sql#L2907:2924)


<context ref="file:///Users/dtavares/dev/OpenCue/cuebot/src/main/resources/conf/ddl/postgres/migrations/V1__Initial_schema.sql#L2907:2924">
CREATE FUNCTION trigger__verify_subscription()
RETURNS TRIGGER AS $body$
BEGIN
    /**
    * Check to see ...

### Prompt 5

On 

[@allocation.rs](file:///Users/dtavares/dev/OpenCue/rust/crates/scheduler/src/allocation.rs)

 :123 failing to update the subscription delta would mean the database has outdated information to continue allow booking. Shouldn't it panic on this condition to force a service restart. This will force a cache reconstruction from procs.


<context ref="file:///Users/dtavares/dev/OpenCue/rust/crates/scheduler/src/allocation.rs">
// Copyright Contributors to the OpenCue Project
//
// Licensed un...

