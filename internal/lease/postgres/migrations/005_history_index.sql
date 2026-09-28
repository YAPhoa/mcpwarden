-- Bounded, indexed history reads (removal plan PR 2). Pages read settled
-- events (everything but admissions) from one index per filter, in history
-- order, and open admissions from history_open. Time ranges filter on
-- history_ns, the order the list already uses. The index predicate matches
-- the query's `settled` expression exactly.
DROP INDEX mcpwarden_security.history_owner_recent;
DROP INDEX mcpwarden_security.history_owner_tool;
DROP INDEX mcpwarden_security.history_owner_upstream;
CREATE INDEX history_owner_recent ON mcpwarden_security.history_events(owner_id, history_ns DESC, event_id COLLATE "C" DESC)
    WHERE (event_type IS NULL OR event_type <> 'tool.dispatch.admitted');
CREATE INDEX history_owner_tool ON mcpwarden_security.history_events(owner_id, tool_id, history_ns DESC, event_id COLLATE "C" DESC)
    WHERE (event_type IS NULL OR event_type <> 'tool.dispatch.admitted');
CREATE INDEX history_owner_upstream ON mcpwarden_security.history_events(owner_id, upstream, history_ns DESC, event_id COLLATE "C" DESC)
    WHERE (event_type IS NULL OR event_type <> 'tool.dispatch.admitted');
CREATE INDEX history_owner_status ON mcpwarden_security.history_events(owner_id, status, history_ns DESC, event_id COLLATE "C" DESC)
    WHERE (event_type IS NULL OR event_type <> 'tool.dispatch.admitted');
CREATE INDEX history_owner_actor ON mcpwarden_security.history_events(owner_id, actor_access_id, history_ns DESC, event_id COLLATE "C" DESC)
    WHERE (event_type IS NULL OR event_type <> 'tool.dispatch.admitted');

-- The latest name snapshot of each tool, for the tool filter. Each history
-- insert moves it forward only, so an out-of-order write never replaces a
-- newer name.
CREATE TABLE mcpwarden_security.history_tools (
    owner_id text NOT NULL,
    tool_id text NOT NULL CHECK (tool_id <> ''),
    tool text NOT NULL,
    upstream text NOT NULL,
    last_ns bigint NOT NULL,
    last_event_id text COLLATE "C" NOT NULL,
    PRIMARY KEY (owner_id, tool_id)
);
INSERT INTO mcpwarden_security.history_tools(owner_id, tool_id, tool, upstream, last_ns, last_event_id)
SELECT DISTINCT ON (h.owner_id, h.tool_id) h.owner_id, h.tool_id, h.tool, h.upstream, h.history_ns, h.event_id
FROM mcpwarden_security.history_events h
WHERE h.tool_id <> '' AND NOT (h.event_type = 'tool.dispatch.admitted' AND EXISTS (
    SELECT 1 FROM mcpwarden_security.history_events c WHERE c.owner_id = h.owner_id AND c.invocation_id = h.invocation_id
    AND c.event_type = 'tool.dispatch.completed'))
ORDER BY h.owner_id, h.tool_id, h.history_ns DESC, h.event_id COLLATE "C" DESC;

-- Admissions whose completion is not stored: exactly the calls the history
-- shows with an unknown outcome.
CREATE TABLE mcpwarden_security.history_open (
    owner_id text NOT NULL,
    invocation_id text NOT NULL,
    history_ns bigint NOT NULL,
    event_id text NOT NULL,
    PRIMARY KEY (owner_id, invocation_id)
);
CREATE INDEX history_open_recent ON mcpwarden_security.history_open(owner_id, history_ns DESC, event_id COLLATE "C" DESC);
INSERT INTO mcpwarden_security.history_open(owner_id, invocation_id, history_ns, event_id)
SELECT h.owner_id, h.invocation_id, h.history_ns, h.event_id
FROM mcpwarden_security.history_events h
WHERE h.event_type = 'tool.dispatch.admitted' AND NOT EXISTS (
    SELECT 1 FROM mcpwarden_security.history_events c WHERE c.owner_id = h.owner_id AND c.invocation_id = h.invocation_id
    AND c.event_type = 'tool.dispatch.completed');
