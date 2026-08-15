const std = @import("std");
const contracts = @import("../../core/terminal/contracts.zig");
const client = @import("../../core/terminal/client.zig");
const identity = @import("../../core/terminal/identity.zig");
const operation = @import("../../core/terminal/operation.zig");
const store = @import("../../core/terminal/store.zig");
const debug_trace = @import("../../core/shared/debug_trace.zig");
const io_mod = @import("../../core/shared/io.zig");
const pathing = @import("../../core/workspace/pathing.zig");
const tool_dispatch = @import("../../core/tooling/tool_dispatch.zig");
const workspace_access = @import("../../core/workspace/workspace_access.zig");

const Allocator = std.mem.Allocator;

const ShellKind = enum { user_login, executable };
const ReturnKind = enum { started, exit, quiet, match };
const PayloadKind = enum { text, keys, controls, paste };
const MonitorConditionKind = enum {
    process_exit,
    exit_code,
    signal,
    output_contains,
    output_matches,
    output_quiet,
    screen_matches,
    tcp_ready,
    http_ready,
    path_exists,
    path_changed,
    path_size,
    custom_probe,
};
const NotifyKind = enum {
    on_match,
    on_state_change,
    on_exit,
    every_check,
    every_n_checks,
    interval,
};
const LifetimeKind = enum { until_match, until_session_end, duration };
const MonitorOperationKind = enum { add, update, pause, @"resume", remove };
const composite_argument_fields = [_][]const u8{
    "shell",
    "return_when",
    "dimensions",
    "initial_monitors",
    "write",
    "monitor",
};

pub const ShellInput = struct {
    kind: ShellKind = .user_login,
    path: ?[]const u8 = null,
    clean_start: bool = false,
};

pub const ReturnInput = struct {
    kind: ReturnKind,
    duration_ms: ?u64 = null,
    pattern: ?[]const u8 = null,
};

pub const DimensionsInput = struct {
    rows: u16,
    columns: u16,
};

pub const WriteInput = struct {
    kind: PayloadKind,
    text: ?[]const u8 = null,
    keys: []const contracts.NamedKey = &.{},
    controls: []const u8 = &.{},
};

pub const MonitorConditionInput = struct {
    kind: MonitorConditionKind,
    pattern: ?[]const u8 = null,
    duration_ms: ?u64 = null,
    exit_code: ?i32 = null,
    signal: ?contracts.Signal = null,
    host: ?[]const u8 = null,
    port: ?u16 = null,
    path: ?[]const u8 = null,
    minimum_bytes: ?u64 = null,
    command: ?[]const u8 = null,
    cwd: ?[]const u8 = null,
};

pub const NotifyInput = struct {
    kind: NotifyKind,
    count: ?u32 = null,
    interval_ms: ?u64 = null,
};

pub const LifetimeInput = struct {
    kind: LifetimeKind,
    duration_ms: ?u64 = null,
};

pub const MonitorDefinitionInput = struct {
    condition: MonitorConditionInput,
    check_interval_ms: ?u64 = null,
    notify: NotifyInput,
    lifetime: LifetimeInput,
};

pub const MonitorOperationInput = struct {
    kind: MonitorOperationKind,
    monitor_id: ?[]const u8 = null,
    definition: ?MonitorDefinitionInput = null,
};

/// Public semantic terminal input. Authority and persistence fields are
/// intentionally absent; Core derives them from the current fx session.
pub const Input = struct {
    action: contracts.Action,
    session_id: ?[]const u8 = null,

    cwd: ?[]const u8 = null,
    command: ?[]const u8 = null,
    shell: ShellInput = .{},
    backend: ?contracts.Backend = null,
    return_when: ?ReturnInput = null,
    wait_ceiling_ms: ?u64 = null,
    dimensions: ?DimensionsInput = null,
    initial_monitors: []const MonitorDefinitionInput = &.{},

    cursor_segment: ?u64 = null,
    cursor_offset: ?u64 = null,
    after_event_id: u64 = 0,
    acknowledge_event_id: ?u64 = null,
    max_events: u16 = 64,

    write: ?WriteInput = null,
    lease: contracts.WriteLeaseIntent = .use,
    monitor: ?MonitorOperationInput = null,

    task_id: ?[]const u8 = null,
    workspace_root: ?[]const u8 = null,
    rows: ?u16 = null,
    columns: ?u16 = null,
    signal: ?contracts.Signal = null,
    close_policy: ?contracts.ClosePolicy = null,
};

pub fn actionFieldNames(action: contracts.Action) []const []const u8 {
    return switch (action) {
        .start => &.{ "action", "cwd", "command", "shell", "backend", "return_when", "wait_ceiling_ms", "dimensions", "initial_monitors" },
        .read => &.{ "action", "session_id", "cursor_segment", "cursor_offset" },
        .screen => &.{ "action", "session_id" },
        .write => &.{ "action", "session_id", "write", "lease" },
        .wait => &.{ "action", "session_id", "return_when", "wait_ceiling_ms" },
        .monitor => &.{ "action", "session_id", "monitor" },
        .inspect => &.{ "action", "session_id", "after_event_id", "acknowledge_event_id", "max_events" },
        .list => &.{ "action", "task_id", "workspace_root", "backend" },
        .resize => &.{ "action", "session_id", "rows", "columns" },
        .signal => &.{ "action", "session_id", "signal" },
        .close => &.{ "action", "session_id", "close_policy" },
    };
}

fn actionAllowsField(action: contracts.Action, field_name: []const u8) bool {
    for (actionFieldNames(action)) |allowed_name| {
        if (std.mem.eql(u8, allowed_name, field_name)) return true;
    }
    return false;
}

fn unexpectedActionField(action: contracts.Action, object: std.json.ObjectMap) ?[]const u8 {
    var fields = object.iterator();
    while (fields.next()) |entry| {
        if (!actionAllowsField(action, entry.key_ptr.*)) return entry.key_ptr.*;
    }
    return null;
}

const OwnedInput = struct {
    parsed: std.json.Parsed(Input),

    fn deinit(self: *OwnedInput) void {
        self.parsed.deinit();
        self.* = undefined;
    }
};

pub fn decode(
    ctx: tool_dispatch.DispatchContext,
    args_json: []const u8,
) tool_dispatch.DispatchError!tool_dispatch.DecodeResult {
    var arena_state = std.heap.ArenaAllocator.init(ctx.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var raw = std.json.parseFromSliceLeaky(
        std.json.Value,
        arena,
        args_json,
        .{ .allocate = .alloc_always },
    ) catch {
        return .{ .failure = try ctx.allocator.dupe(
            u8,
            "terminal arguments must match the advertised action schema",
        ) };
    };
    if (raw != .object) {
        return .{ .failure = try ctx.allocator.dupe(
            u8,
            "terminal arguments must match the advertised action schema",
        ) };
    }
    const raw_action = raw.object.get("action") orelse {
        return .{ .failure = try ctx.allocator.dupe(
            u8,
            "terminal arguments must match the advertised action schema",
        ) };
    };
    if (raw_action != .string) {
        return .{ .failure = try ctx.allocator.dupe(
            u8,
            "terminal arguments must match the advertised action schema",
        ) };
    }
    const action = std.meta.stringToEnum(contracts.Action, raw_action.string) orelse {
        return .{ .failure = try ctx.allocator.dupe(
            u8,
            "terminal arguments must match the advertised action schema",
        ) };
    };
    if (unexpectedActionField(action, raw.object)) |field_name| {
        return .{ .failure = try std.fmt.allocPrint(
            ctx.allocator,
            "terminal {s} field \"{s}\" is not allowed",
            .{ @tagName(action), field_name },
        ) };
    }

    normalizeCompositeArguments(arena, &raw) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => {
            return .{ .failure = try ctx.allocator.dupe(
                u8,
                "terminal arguments must match the advertised action schema",
            ) };
        },
    };

    var normalized: std.Io.Writer.Allocating = .init(ctx.allocator);
    defer normalized.deinit();
    std.json.Stringify.value(raw, .{}, &normalized.writer) catch
        return error.OutOfMemory;
    const normalized_json = try normalized.toOwnedSlice();
    defer ctx.allocator.free(normalized_json);

    const parsed = std.json.parseFromSlice(
        Input,
        ctx.allocator,
        normalized_json,
        .{ .allocate = .alloc_always },
    ) catch {
        return .{ .failure = try ctx.allocator.dupe(
            u8,
            "terminal arguments must match the advertised action schema",
        ) };
    };
    const owned = try ctx.allocator.create(OwnedInput);
    owned.* = .{ .parsed = parsed };
    return .{ .input = .{
        .ptr = owned,
        .deinit_fn = inputDeinit,
    } };
}

fn normalizeCompositeArguments(
    alloc: Allocator,
    root: *std.json.Value,
) !void {
    for (composite_argument_fields) |field_name| {
        const value = root.object.getPtr(field_name) orelse continue;
        if (value.* != .string) continue;
        const decoded = try std.json.parseFromSliceLeaky(
            std.json.Value,
            alloc,
            value.string,
            .{ .allocate = .alloc_always },
        );
        if (decoded != .object and decoded != .array) {
            return error.InvalidCompositeArgument;
        }
        value.* = decoded;
    }

    const initial_monitors = root.object.getPtr("initial_monitors") orelse return;
    if (initial_monitors.* != .array) return;
    for (initial_monitors.array.items) |*monitor| {
        if (monitor.* != .object) continue;
        const condition = monitor.object.getPtr("condition") orelse continue;
        if (condition.* != .object) continue;
        const interval = condition.object.get("check_interval_ms") orelse continue;
        _ = condition.object.orderedRemove("check_interval_ms");
        if (monitor.object.get("check_interval_ms") == null) {
            try monitor.object.put(alloc, "check_interval_ms", interval);
        }
    }
}

fn inputDeinit(ptr: *anyopaque, alloc: Allocator) void {
    const input: *OwnedInput = @ptrCast(@alignCast(ptr));
    input.deinit();
    alloc.destroy(input);
}

pub fn validate(
    ctx: tool_dispatch.DispatchContext,
    erased: tool_dispatch.ToolInput,
) tool_dispatch.DispatchError!?[]u8 {
    const input = &erased.as(OwnedInput).parsed.value;
    var arena_state = std.heap.ArenaAllocator.init(ctx.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const request = semanticRequest(arena, ctx, input) catch |err| {
        return @as(?[]u8, try std.fmt.allocPrint(
            ctx.allocator,
            "terminal {s} arguments are invalid: {s}",
            .{ @tagName(input.action), @errorName(err) },
        ));
    };
    request.validate() catch |err| {
        return @as(?[]u8, try std.fmt.allocPrint(
            ctx.allocator,
            "terminal {s} arguments are invalid: {s}",
            .{ @tagName(input.action), @errorName(err) },
        ));
    };
    return null;
}

pub fn call(
    ctx: tool_dispatch.DispatchContext,
    erased: tool_dispatch.ToolInput,
) tool_dispatch.DispatchError!tool_dispatch.ToolResult {
    const runtime = ctx.terminal_client orelse return structuredFailure(
        ctx.allocator,
        erased.as(OwnedInput).parsed.value.action,
        null,
        .unsupported_host,
        false,
    );
    const owner = ctx.session_child_capability orelse return structuredFailure(
        ctx.allocator,
        erased.as(OwnedInput).parsed.value.action,
        null,
        .authority_denied,
        false,
    );
    const durable_session_id = ctx.terminal_owner_session_id orelse
        return structuredFailure(
            ctx.allocator,
            erased.as(OwnedInput).parsed.value.action,
            null,
            .authority_denied,
            false,
        );
    const input = &erased.as(OwnedInput).parsed.value;

    var arena_state = std.heap.ArenaAllocator.init(ctx.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var profile_user_buffer: [64]u8 = undefined;
    const profile_user = identity.profileUser(&profile_user_buffer) orelse return structuredFailure(
        ctx.allocator,
        input.action,
        input.session_id,
        .unsupported_host,
        false,
    );

    var request = buildRequest(
        arena,
        ctx,
        owner,
        durable_session_id,
        profile_user,
        input,
    ) catch |err| {
        debug_trace.logf(
            "terminal",
            "public request preparation failed action={s} err={s}",
            .{ @tagName(input.action), @errorName(err) },
        );
        if (err == error.TerminalSessionNotFound and
            input.action == .list and input.session_id == null)
        {
            return stringifyResult(ctx.allocator, .{ .success = .{
                .list = .{ .sessions = &.{} },
            } });
        }
        return structuredFailure(
            ctx.allocator,
            input.action,
            input.session_id,
            mapErrorCode(err),
            false,
        );
    };
    defer request.deinit();

    const correlation_id = runtime.nextCorrelationId();
    runtime.admit(
        ctx.background_lifecycle_allocator,
        correlation_id,
        request.value,
    ) catch |err| {
        debug_trace.logf(
            "terminal",
            "public request admission failed action={s} err={s}",
            .{ @tagName(input.action), @errorName(err) },
        );
        return structuredFailure(
            ctx.allocator,
            input.action,
            request.sessionId(),
            mapErrorCode(err),
            err == error.QueueFull,
        );
    };

    var cancellation_sent = false;
    while (true) {
        if (runtime.takeCompletionFor(correlation_id)) |completion_value| {
            var completion = completion_value;
            defer completion.deinit();
            return resultFromCompletion(
                ctx.allocator,
                input.action,
                request.sessionId(),
                completion,
            );
        }
        if (!cancellation_sent) {
            if (ctx.cancel_flag) |cancel_flag| {
                if (cancel_flag.load(.acquire)) {
                    _ = runtime.cancel(correlation_id);
                    cancellation_sent = true;
                }
            }
        }
        io_mod.sleep(2 * std.time.ns_per_ms);
    }
}

const PreparedRequest = struct {
    value: contracts.ActionRequest,
    authority: ?operation.OwnedAuthorityClaim = null,
    owner_authority: ?operation.OwnedOwnerCatalogClaim = null,
    persistence: ?operation.PreparedAuthority = null,

    fn sessionId(self: *const PreparedRequest) ?[]const u8 {
        return operation.authoritySessionId(self.value);
    }

    fn deinit(self: *PreparedRequest) void {
        if (self.authority) |*authority| authority.deinit();
        if (self.owner_authority) |*authority| authority.deinit();
        if (self.persistence) |*persistence| persistence.deinit();
        self.* = undefined;
    }
};

fn buildRequest(
    arena: Allocator,
    ctx: tool_dispatch.DispatchContext,
    owner: *@import("../../core/session/session_child_store.zig").SessionChildCapability,
    durable_session_id: []const u8,
    profile_user: []const u8,
    input: *const Input,
) !PreparedRequest {
    if (input.action == .start) {
        const cwd = try resolveCwd(arena, ctx, input.cwd);
        const definitions = try buildMonitorDefinitions(arena, input.initial_monitors);
        const repeated_probes = try repeatedProbeAuthority(arena, definitions);
        var persistence = try operation.prepareStartPersistence(arena, .{
            .profile_user = profile_user,
            .durable_session_id = durable_session_id,
            .workspace_root = ctx.workspace_root,
            .cwd = cwd,
            .transport_role = ctx.terminal_transport_role,
            .sandbox_backend = ctx.sandbox_backend,
            .backend = input.backend orelse .native,
            .actor = .agent,
            .controls = .full(),
            .lifetime = .session,
            .repeated_probes = repeated_probes,
        });
        errdefer persistence.deinit();
        const request = startRequest(input, cwd, definitions, persistence.view()) catch |err| {
            return err;
        };
        try operation.validate(request);
        return .{ .value = request, .persistence = persistence };
    }

    if (input.action == .list) {
        var owner_authority = try store.loadOrCreateOwnerCatalogClaim(
            arena,
            owner,
            .{
                .profile_user = profile_user,
                .durable_session_id = durable_session_id,
                .workspace_root = ctx.workspace_root,
                .transport_role = ctx.terminal_transport_role,
                .sandbox_backend = ctx.sandbox_backend,
                .actor = .agent,
            },
        );
        errdefer owner_authority.deinit();
        const request = try build_list_request(
            arena,
            ctx,
            input,
            owner_authority.view(),
        );
        try operation.validate(request);
        return .{ .value = request, .owner_authority = owner_authority };
    }

    const authority_session_id = try arena.dupe(
        u8,
        input.session_id orelse return error.InvalidSessionId,
    );
    var authority = try store.reloadOwnerAuthorityClaim(arena, owner, .{
        .terminal_session_id = authority_session_id,
        .profile_user = profile_user,
        .durable_session_id = durable_session_id,
        .workspace_root = ctx.workspace_root,
        .transport_role = ctx.terminal_transport_role,
        .sandbox_backend = ctx.sandbox_backend,
        .actor = .agent,
    });
    errdefer authority.deinit();
    const claim = authority.view();
    const request = try buildAuthorizedRequest(arena, input, authority_session_id, claim);
    try operation.validate(request);
    return .{ .value = request, .authority = authority };
}

fn buildAuthorizedRequest(
    arena: Allocator,
    input: *const Input,
    session_id: []const u8,
    authority: ?contracts.AuthorityClaim,
) !contracts.ActionRequest {
    return switch (input.action) {
        .start => unreachable,
        .read => .{ .read = .{
            .session_id = session_id,
            .cursor = .{
                .segment = input.cursor_segment orelse return error.InvalidRawCursor,
                .offset = input.cursor_offset orelse 0,
            },
            .authority = authority,
        } },
        .screen => .{ .screen = .{
            .session_id = session_id,
            .authority = authority,
        } },
        .write => .{ .write = .{
            .session_id = session_id,
            .payload = if (input.lease == .use)
                try buildWritePayload(arena, input.write orelse
                    return error.InvalidWritePayload)
            else
                null,
            .lease = input.lease,
            .authority = authority,
        } },
        .wait => .{ .wait = .{
            .session_id = session_id,
            .return_when = try buildReturnCondition(input.return_when orelse
                return error.MissingReturnCondition),
            .safety_ceiling_ms = input.wait_ceiling_ms orelse
                return error.MissingWaitCeiling,
            .authority = authority,
        } },
        .monitor => .{ .monitor = .{
            .session_id = session_id,
            .operation = try buildMonitorOperation(
                input.monitor orelse return error.InvalidMonitor,
            ),
            .authority = authority,
        } },
        .inspect => .{ .inspect = .{
            .session_id = session_id,
            .authority = authority,
            .after_event_id = input.after_event_id,
            .acknowledge_event_id = input.acknowledge_event_id,
            .max_events = input.max_events,
        } },
        .list => unreachable,
        .resize => .{ .resize = .{
            .session_id = session_id,
            .dimensions = .{
                .rows = input.rows orelse return error.InvalidDimensions,
                .columns = input.columns orelse return error.InvalidDimensions,
            },
            .authority = authority,
        } },
        .signal => .{ .signal = .{
            .session_id = session_id,
            .signal = input.signal orelse return error.InvalidRequest,
            .authority = authority,
        } },
        .close => .{ .close = .{
            .session_id = session_id,
            .policy = input.close_policy orelse return error.InvalidRequest,
            .authority = authority,
        } },
    };
}

fn semanticRequest(
    arena: Allocator,
    ctx: tool_dispatch.DispatchContext,
    input: *const Input,
) !contracts.ActionRequest {
    if (input.action == .start) {
        const cwd = try resolveCwd(arena, ctx, input.cwd);
        const definitions = try buildMonitorDefinitions(arena, input.initial_monitors);
        return startRequest(input, cwd, definitions, null);
    }
    if (input.action == .list) {
        return build_list_request(arena, ctx, input, null);
    }
    const session_id = input.session_id orelse return error.InvalidSessionId;
    return buildAuthorizedRequest(arena, input, session_id, null);
}

fn project_list_filters(input: *const Input) contracts.ListFilters {
    return .{
        .task_id = if (input.task_id) |task_id|
            if (task_id.len == 0) null else task_id
        else
            null,
        .workspace_root = if (input.workspace_root) |workspace_root|
            if (workspace_root.len == 0) null else workspace_root
        else
            null,
        .backend = input.backend,
    };
}

fn build_list_request(
    arena: Allocator,
    ctx: tool_dispatch.DispatchContext,
    input: *const Input,
    owner_authority: ?contracts.OwnerCatalogAuthorityClaim,
) !contracts.ActionRequest {
    var filters = project_list_filters(input);
    if (filters.workspace_root) |root| {
        filters.workspace_root = try resolveCwd(arena, ctx, root);
    }
    filters.owner_authority = owner_authority;
    return .{ .list = filters };
}

fn startRequest(
    input: *const Input,
    cwd: []const u8,
    definitions: []const contracts.MonitorDefinition,
    persistence: ?contracts.StartPersistence,
) !contracts.ActionRequest {
    const command: ?[]const u8 = if (input.command) |value|
        if (value.len == 0) null else value
    else
        null;
    return .{ .start = .{
        .cwd = cwd,
        .command = command,
        .shell = try buildShell(input.shell),
        .backend = input.backend orelse .native,
        .return_when = if (input.return_when) |condition|
            try buildReturnCondition(condition)
        else if (command != null)
            .started
        else
            null,
        .wait_ceiling_ms = input.wait_ceiling_ms,
        .dimensions = if (input.dimensions) |value|
            .{ .rows = value.rows, .columns = value.columns }
        else
            null,
        .initial_monitors = definitions,
        .persistence = persistence,
    } };
}

fn resolveCwd(
    arena: Allocator,
    ctx: tool_dispatch.DispatchContext,
    requested: ?[]const u8,
) ![]const u8 {
    const scope = ctx.access_scope orelse
        workspace_access.AccessScope.primaryOnly(ctx.workspace_root);
    const value = requested orelse return arena.dupe(u8, scope.primary_directory);
    if (std.mem.eql(u8, value, ".")) {
        return arena.dupe(u8, scope.primary_directory);
    }
    return pathing.resolveWorkspaceOrExternalPath(
        arena,
        scope.primary_directory,
        value,
    );
}

fn buildShell(input: ShellInput) !contracts.ShellSpec {
    return switch (input.kind) {
        .user_login => .user_login,
        .executable => .{ .executable = .{
            .path = input.path orelse return error.InvalidShell,
            .clean_start = input.clean_start,
        } },
    };
}

fn buildReturnCondition(input: ReturnInput) !contracts.ReturnCondition {
    return switch (input.kind) {
        .started => .started,
        .exit => .exit,
        .quiet => .{ .quiet = input.duration_ms orelse
            return error.InvalidReturnCondition },
        .match => .{ .match = input.pattern orelse
            return error.InvalidReturnCondition },
    };
}

fn buildWritePayload(
    arena: Allocator,
    input: WriteInput,
) !contracts.WritePayload {
    return switch (input.kind) {
        .text => .{ .text = input.text orelse return error.InvalidWritePayload },
        .paste => .{ .paste = input.text orelse return error.InvalidWritePayload },
        .keys => .{ .keys = input.keys },
        .controls => blk: {
            const controls = try arena.alloc(
                contracts.ControlInput,
                input.controls.len,
            );
            for (input.controls, 0..) |character, index| {
                controls[index] = .{ .character = character };
            }
            break :blk .{ .controls = controls };
        },
    };
}

fn buildMonitorDefinitions(
    arena: Allocator,
    inputs: []const MonitorDefinitionInput,
) ![]contracts.MonitorDefinition {
    const definitions = try arena.alloc(contracts.MonitorDefinition, inputs.len);
    for (inputs, 0..) |input, index| {
        definitions[index] = try buildMonitorDefinition(input);
    }
    return definitions;
}

fn buildMonitorDefinition(input: MonitorDefinitionInput) !contracts.MonitorDefinition {
    const condition = try buildMonitorCondition(input.condition);
    return .{
        .condition = condition,
        .check_schedule = if (condition.requires_polling())
            .{ .interval_ms = input.check_interval_ms orelse
                return error.MissingCheckSchedule }
        else
            null,
        .notify_schedule = try buildNotifySchedule(input.notify),
        .lifetime = try buildMonitorLifetime(input.lifetime),
    };
}

fn buildMonitorCondition(input: MonitorConditionInput) !contracts.MonitorCondition {
    return switch (input.kind) {
        .process_exit => .process_exit,
        .exit_code => .{ .exit_code = input.exit_code orelse
            return error.InvalidMonitorCondition },
        .signal => .{ .signal = input.signal orelse
            return error.InvalidMonitorCondition },
        .output_contains => .{ .output_contains = input.pattern orelse
            return error.InvalidMonitorCondition },
        .output_matches => .{ .output_matches = input.pattern orelse
            return error.InvalidMonitorCondition },
        .output_quiet => .{ .output_quiet_ms = input.duration_ms orelse
            return error.InvalidMonitorCondition },
        .screen_matches => .{ .screen_matches = input.pattern orelse
            return error.InvalidMonitorCondition },
        .tcp_ready => .{ .tcp_ready = .{
            .host = input.host orelse return error.InvalidMonitorCondition,
            .port = input.port orelse return error.InvalidMonitorCondition,
        } },
        .http_ready => .{ .http_ready = input.pattern orelse
            return error.InvalidMonitorCondition },
        .path_exists => .{ .path_exists = input.path orelse
            return error.InvalidMonitorCondition },
        .path_changed => .{ .path_changed = input.path orelse
            return error.InvalidMonitorCondition },
        .path_size => .{ .path_size = .{
            .path = input.path orelse return error.InvalidMonitorCondition,
            .minimum_bytes = input.minimum_bytes orelse
                return error.InvalidMonitorCondition,
        } },
        .custom_probe => .{ .custom_probe = .{
            .command = input.command orelse return error.InvalidMonitorCondition,
            .cwd = input.cwd orelse return error.InvalidMonitorCondition,
        } },
    };
}

fn buildNotifySchedule(input: NotifyInput) !contracts.NotifySchedule {
    return switch (input.kind) {
        .on_match => .on_match,
        .on_state_change => .on_state_change,
        .on_exit => .on_exit,
        .every_check => .every_check,
        .every_n_checks => .{ .every_n_checks = input.count orelse
            return error.InvalidSchedule },
        .interval => .{ .interval = .{
            .interval_ms = input.interval_ms orelse return error.InvalidSchedule,
        } },
    };
}

fn buildMonitorLifetime(input: LifetimeInput) !contracts.MonitorLifetime {
    return switch (input.kind) {
        .until_match => .until_match,
        .until_session_end => .until_session_end,
        .duration => .{ .duration_ms = input.duration_ms orelse
            return error.InvalidMonitorLifetime },
    };
}

fn buildMonitorOperation(input: MonitorOperationInput) !contracts.MonitorOperation {
    return switch (input.kind) {
        .add => .{ .add = try buildMonitorDefinition(input.definition orelse
            return error.InvalidMonitor) },
        .update => .{ .update = .{
            .monitor_id = input.monitor_id orelse return error.InvalidMonitor,
            .definition = try buildMonitorDefinition(input.definition orelse
                return error.InvalidMonitor),
        } },
        .pause => .{ .pause = input.monitor_id orelse return error.InvalidMonitor },
        .@"resume" => .{ .@"resume" = input.monitor_id orelse
            return error.InvalidMonitor },
        .remove => .{ .remove = input.monitor_id orelse return error.InvalidMonitor },
    };
}

fn repeatedProbeAuthority(
    arena: Allocator,
    definitions: []const contracts.MonitorDefinition,
) ![]contracts.RepeatedProbeAuthority {
    var count: usize = 0;
    for (definitions) |definition| {
        if (definition.condition == .custom_probe) count += 1;
    }
    const probes = try arena.alloc(contracts.RepeatedProbeAuthority, count);
    var index: usize = 0;
    for (definitions) |definition| {
        if (definition.condition != .custom_probe) continue;
        const probe = definition.condition.custom_probe;
        probes[index] = .{
            .command = probe.command,
            .cwd = probe.cwd,
            .check_schedule = definition.check_schedule orelse
                return error.MissingCheckSchedule,
            .notify_schedule = definition.notify_schedule,
            .lifetime = definition.lifetime,
        };
        index += 1;
    }
    return probes;
}

fn resultFromCompletion(
    alloc: Allocator,
    action: contracts.Action,
    session_id: ?[]const u8,
    completion: client.Completion,
) tool_dispatch.DispatchError!tool_dispatch.ToolResult {
    if (completion.frame) |*frame| {
        return switch (frame.message().payload) {
            .response => |response| stringifyResult(alloc, response),
            else => structuredFailure(
                alloc,
                action,
                session_id,
                .protocol_incompatible,
                false,
            ),
        };
    }
    return structuredFailure(
        alloc,
        action,
        session_id,
        switch (completion.kind) {
            .cancelled => .cancelled,
            .unavailable => .protocol_incompatible,
            .disconnected => .session_lost,
            .response => .protocol_incompatible,
        },
        completion.kind == .disconnected,
    );
}

fn stringifyResult(
    alloc: Allocator,
    result: contracts.Result,
) tool_dispatch.DispatchError!tool_dispatch.ToolResult {
    var out: std.Io.Writer.Allocating = .init(alloc);
    defer out.deinit();
    std.json.Stringify.value(result, .{}, &out.writer) catch
        return error.OutOfMemory;
    const body = try out.toOwnedSlice();
    return switch (result) {
        .success => .{ .success = body },
        .failure => .{ .failure = body },
    };
}

pub fn mapAuthorizedResult(
    alloc: Allocator,
    result: tool_dispatch.DispatchResult,
) Allocator.Error!tool_dispatch.DispatchResult {
    if (result.status != .failure or result.status_detail != null) return result;
    var parsed = std.json.parseFromSlice(
        contracts.Result,
        alloc,
        result.body,
        .{},
    ) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return result,
    };
    defer parsed.deinit();
    const code = switch (parsed.value) {
        .success => return result,
        .failure => |failure| failure.code,
    };
    if (code != .path_outside_workspace) return result;

    var mapped = result;
    mapped.status_detail = try alloc.dupe(u8, "path is outside the workspace");
    return mapped;
}

fn structuredFailure(
    alloc: Allocator,
    action: contracts.Action,
    session_id: ?[]const u8,
    code: contracts.StructuredErrorCode,
    retryable: bool,
) tool_dispatch.DispatchError!tool_dispatch.ToolResult {
    return stringifyResult(alloc, .{ .failure = .{
        .action = action,
        .code = code,
        .session_id = session_id,
        .retryable = retryable,
    } });
}

fn mapErrorCode(err: anyerror) contracts.StructuredErrorCode {
    return switch (err) {
        error.TerminalSessionNotFound,
        error.InvalidSessionId,
        => .session_not_found,
        error.QueueFull, error.CapacityExceeded => .capacity_exceeded,
        error.ProtocolIncompatible => .protocol_incompatible,
        error.AuthorityRevoked,
        error.ActorRoleMismatch,
        error.PrincipalMismatch,
        error.StaleAuthorityGeneration,
        error.InvalidHolderProof,
        error.ControlDenied,
        => .authority_denied,
        error.Cancelled => .cancelled,
        else => .invalid_request,
    };
}

pub fn readsOnly(erased: tool_dispatch.ToolInput) bool {
    const input = erased.as(OwnedInput).parsed.value;
    return switch (input.action) {
        .read, .screen, .list => true,
        .inspect => input.acknowledge_event_id == null,
        else => false,
    };
}

pub fn isIrreversible(_: tool_dispatch.ToolInput) bool {
    return false;
}

test "terminal decoder accepts every public action and owns its input" {
    const alloc = std.testing.allocator;
    inline for (std.meta.tags(contracts.Action)) |action| {
        const args = try std.fmt.allocPrint(
            alloc,
            "{{\"action\":\"{s}\"}}",
            .{@tagName(action)},
        );
        defer alloc.free(args);
        const decoded = try decode(.{ .allocator = alloc }, args);
        switch (decoded) {
            .failure => |message| {
                defer alloc.free(message);
                return error.TestUnexpectedResult;
            },
            .input => |input| {
                defer input.deinit(alloc);
                try std.testing.expectEqual(
                    action,
                    input.as(OwnedInput).parsed.value.action,
                );
            },
        }
    }
}

test "terminal action field ownership is exact for every public action" {
    const expected = [_]struct {
        action: contracts.Action,
        fields: []const []const u8,
    }{
        .{ .action = .start, .fields = &.{ "action", "cwd", "command", "shell", "backend", "return_when", "wait_ceiling_ms", "dimensions", "initial_monitors" } },
        .{ .action = .read, .fields = &.{ "action", "session_id", "cursor_segment", "cursor_offset" } },
        .{ .action = .screen, .fields = &.{ "action", "session_id" } },
        .{ .action = .write, .fields = &.{ "action", "session_id", "write", "lease" } },
        .{ .action = .wait, .fields = &.{ "action", "session_id", "return_when", "wait_ceiling_ms" } },
        .{ .action = .monitor, .fields = &.{ "action", "session_id", "monitor" } },
        .{ .action = .inspect, .fields = &.{ "action", "session_id", "after_event_id", "acknowledge_event_id", "max_events" } },
        .{ .action = .list, .fields = &.{ "action", "task_id", "workspace_root", "backend" } },
        .{ .action = .resize, .fields = &.{ "action", "session_id", "rows", "columns" } },
        .{ .action = .signal, .fields = &.{ "action", "session_id", "signal" } },
        .{ .action = .close, .fields = &.{ "action", "session_id", "close_policy" } },
    };

    try std.testing.expectEqual(std.meta.tags(contracts.Action).len, expected.len);
    for (expected) |want| {
        try std.testing.expectEqualSlices(
            []const u8,
            want.fields,
            actionFieldNames(want.action),
        );
        inline for (@typeInfo(Input).@"struct".fields) |field| {
            var want_allowed = false;
            for (want.fields) |allowed_name| {
                if (std.mem.eql(u8, allowed_name, field.name)) {
                    want_allowed = true;
                    break;
                }
            }
            try std.testing.expectEqual(
                want_allowed,
                actionAllowsField(want.action, field.name),
            );
        }
    }
}

test "terminal decoder rejects cross-action fields regardless of value" {
    const alloc = std.testing.allocator;
    inline for (&.{
        .{
            "{\"action\":\"start\",\"session_id\":\"\"}",
            "terminal start field \"session_id\" is not allowed",
        },
        .{
            "{\"action\":\"list\",\"cwd\":\"\",\"task_id\":\"\"}",
            "terminal list field \"cwd\" is not allowed",
        },
        .{
            "{\"action\":\"close\",\"close_policy\":\"force\",\"session_id\":\"terminal-a\",\"rows\":0}",
            "terminal close field \"rows\" is not allowed",
        },
    }) |case| {
        const decoded = try decode(.{ .allocator = alloc }, case[0]);
        switch (decoded) {
            .failure => |message| {
                defer alloc.free(message);
                try std.testing.expectEqualStrings(case[1], message);
            },
            .input => |input| {
                input.deinit(alloc);
                return error.TestUnexpectedResult;
            },
        }
    }
}

test "terminal start accepts native and tmux backend contracts" {
    const alloc = std.testing.allocator;
    inline for (.{ "native", "tmux" }) |backend| {
        const args = try std.fmt.allocPrint(
            alloc,
            "{{\"action\":\"start\",\"command\":\"true\",\"backend\":\"{s}\",\"return_when\":{{\"kind\":\"exit\"}},\"wait_ceiling_ms\":5000}}",
            .{backend},
        );
        defer alloc.free(args);
        const decoded = try decode(.{ .allocator = alloc }, args);
        switch (decoded) {
            .failure => |message| {
                defer alloc.free(message);
                return error.TestUnexpectedResult;
            },
            .input => |input| {
                defer input.deinit(alloc);
                const reason = try validate(.{
                    .allocator = alloc,
                    .workspace_root = "/tmp",
                }, input);
                if (reason) |message| {
                    defer alloc.free(message);
                    return error.TestUnexpectedResult;
                }
            },
        }
    }
}

test "terminal decoder normalizes gateway stringified start composites" {
    const alloc = std.testing.allocator;
    const args =
        "{\"action\":\"start\",\"cwd\":\"/workspace\",\"backend\":\"native\",\"command\":\"printf SHOULD_NOT_RUN\",\"return_when\":\"{\\\"kind\\\":\\\"started\\\"}\",\"initial_monitors\":\"[{\\\"condition\\\":{\\\"kind\\\":\\\"path_exists\\\",\\\"path\\\":\\\"/private/tmp/fx-monitor-outside-ready\\\",\\\"check_interval_ms\\\":1000},\\\"notify\\\":{\\\"kind\\\":\\\"on_match\\\"},\\\"lifetime\\\":{\\\"kind\\\":\\\"until_match\\\"}}]\"}";
    const decoded = try decode(.{ .allocator = alloc }, args);
    switch (decoded) {
        .failure => |message| {
            defer alloc.free(message);
            return error.TestUnexpectedResult;
        },
        .input => |input| {
            defer input.deinit(alloc);
            const parsed = input.as(OwnedInput).parsed.value;
            try std.testing.expectEqual(ReturnKind.started, parsed.return_when.?.kind);
            try std.testing.expectEqual(@as(usize, 1), parsed.initial_monitors.len);
            const monitor = parsed.initial_monitors[0];
            try std.testing.expectEqual(MonitorConditionKind.path_exists, monitor.condition.kind);
            try std.testing.expectEqualStrings(
                "/private/tmp/fx-monitor-outside-ready",
                monitor.condition.path.?,
            );
            try std.testing.expectEqual(@as(?u64, 1000), monitor.check_interval_ms);
            try std.testing.expectEqual(NotifyKind.on_match, monitor.notify.kind);
            try std.testing.expectEqual(LifetimeKind.until_match, monitor.lifetime.kind);
        },
    }
}

test "terminal decoder rejects malformed gateway composite strings" {
    const alloc = std.testing.allocator;
    const decoded = try decode(
        .{ .allocator = alloc },
        "{\"action\":\"start\",\"return_when\":\"not-json\"}",
    );
    switch (decoded) {
        .input => |input| {
            input.deinit(alloc);
            return error.TestUnexpectedResult;
        },
        .failure => |message| {
            defer alloc.free(message);
            try std.testing.expectEqualStrings(
                "terminal arguments must match the advertised action schema",
                message,
            );
        },
    }
}

test "terminal start canonicalizes interactive command representations" {
    const ReturnTag = std.meta.Tag(contracts.ReturnCondition);
    const cases = [_]struct {
        input: Input,
        expected_command: ?[]const u8,
        expected_return_when: ?ReturnTag,
    }{
        .{
            .input = .{ .action = .start },
            .expected_command = null,
            .expected_return_when = null,
        },
        .{
            .input = .{ .action = .start, .command = "" },
            .expected_command = null,
            .expected_return_when = null,
        },
        .{
            .input = .{ .action = .start, .command = "printf ready" },
            .expected_command = "printf ready",
            .expected_return_when = .started,
        },
        .{
            .input = .{
                .action = .start,
                .command = "",
                .return_when = .{ .kind = .exit },
                .wait_ceiling_ms = 1000,
            },
            .expected_command = null,
            .expected_return_when = .exit,
        },
        .{
            .input = .{ .action = .start, .command = " " },
            .expected_command = " ",
            .expected_return_when = .started,
        },
    };

    for (cases) |case| {
        const request = try startRequest(&case.input, "/tmp", &.{}, null);
        try request.validate();
        switch (request) {
            .start => |start| {
                if (case.expected_command) |expected| {
                    try std.testing.expectEqualStrings(expected, start.command.?);
                } else {
                    try std.testing.expect(start.command == null);
                }
                if (case.expected_return_when) |expected| {
                    try std.testing.expectEqual(
                        expected,
                        std.meta.activeTag(start.return_when.?),
                    );
                } else {
                    try std.testing.expect(start.return_when == null);
                }
            },
            else => return error.TestUnexpectedResult,
        }
    }
}

test "registered terminal validation enforces action-specific input before execution" {
    const terminal_tool = tool_dispatch.Tool{
        .name = "terminal",
        .description = "Terminal test adapter.",
        .descriptor = .{
            .name = "terminal",
            .description = "Terminal test adapter.",
        },
        .decode = decode,
        .validate = validate,
        .call = call,
        .reads_only_fn = readsOnly,
        .irreversible_fn = isIrreversible,
    };
    const registry = tool_dispatch.Registry{ .tools = &.{terminal_tool} };
    const ctx: tool_dispatch.DispatchContext = .{
        .allocator = std.testing.allocator,
        .workspace_root = "/tmp",
    };

    inline for (&.{
        "{\"action\":\"start\",\"command\":\"\"}",
        "{\"action\":\"read\",\"session_id\":\"terminal-a\",\"cursor_segment\":1}",
        "{\"action\":\"screen\",\"session_id\":\"terminal-a\"}",
        "{\"action\":\"write\",\"session_id\":\"terminal-a\",\"lease\":\"acquire\"}",
        "{\"action\":\"wait\",\"session_id\":\"terminal-a\",\"return_when\":{\"kind\":\"exit\"},\"wait_ceiling_ms\":1000}",
        "{\"action\":\"monitor\",\"session_id\":\"terminal-a\",\"monitor\":{\"kind\":\"remove\",\"monitor_id\":\"monitor-a\"}}",
        "{\"action\":\"inspect\",\"session_id\":\"terminal-a\"}",
        "{\"action\":\"list\",\"task_id\":\"\",\"workspace_root\":\"\"}",
        "{\"action\":\"resize\",\"session_id\":\"terminal-a\",\"rows\":24,\"columns\":80}",
        "{\"action\":\"signal\",\"session_id\":\"terminal-a\",\"signal\":\"interrupt\"}",
        "{\"action\":\"close\",\"session_id\":\"terminal-a\",\"close_policy\":\"force\"}",
    }) |arguments_json| {
        const accepted = try tool_dispatch.validateRegisteredToolCall(ctx, registry, .{
            .id = "terminal-valid",
            .name = "terminal",
            .arguments_json = arguments_json,
        });
        defer switch (accepted) {
            .failure => |reason| std.testing.allocator.free(reason),
            else => {},
        };
        try std.testing.expectEqual(.valid, accepted);
    }

    const mixed = try tool_dispatch.validateRegisteredToolCall(ctx, registry, .{
        .id = "terminal-mixed-start",
        .name = "terminal",
        .arguments_json = "{\"action\":\"start\",\"command\":\"printf wrong\",\"session_id\":\"terminal-a\",\"write\":{\"kind\":\"text\",\"text\":\"wrong\"},\"rows\":24,\"columns\":80,\"signal\":\"terminate\",\"close_policy\":\"force\"}",
    });
    defer switch (mixed) {
        .failure => |reason| std.testing.allocator.free(reason),
        else => {},
    };
    switch (mixed) {
        .failure => |reason| try std.testing.expect(
            std.mem.find(u8, reason, "terminal start field \"session_id\" is not allowed") != null,
        ),
        else => return error.TestUnexpectedResult,
    }

    const rejected = try tool_dispatch.validateRegisteredToolCall(ctx, registry, .{
        .id = "terminal-invalid-resize",
        .name = "terminal",
        .arguments_json = "{\"action\":\"resize\"}",
    });
    defer switch (rejected) {
        .failure => |reason| std.testing.allocator.free(reason),
        else => {},
    };
    try std.testing.expect(rejected == .failure);
}

test "terminal result mapper adds detail only for workspace path failures" {
    const alloc = std.testing.allocator;
    const cases = [_]struct {
        status: tool_dispatch.DispatchResult.Status,
        body: []const u8,
        expected_detail: ?[]const u8,
    }{
        .{
            .status = .failure,
            .body = "{\"failure\":{\"action\":\"start\",\"code\":\"path_outside_workspace\",\"session_id\":null,\"retryable\":false}}",
            .expected_detail = "path is outside the workspace",
        },
        .{
            .status = .failure,
            .body = "{\"failure\":{\"action\":\"start\",\"code\":\"invalid_request\",\"session_id\":null,\"retryable\":false}}",
            .expected_detail = null,
        },
        .{ .status = .failure, .body = "not json", .expected_detail = null },
        .{
            .status = .success,
            .body = "{\"success\":{\"close\":{\"session\":{}}}}",
            .expected_detail = null,
        },
    };

    for (cases) |case| {
        const body = try alloc.dupe(u8, case.body);
        var mapped = try mapAuthorizedResult(alloc, .{
            .status = case.status,
            .body = body,
        });
        defer mapped.deinit(alloc);
        try std.testing.expectEqualStrings(case.body, mapped.body);
        if (case.expected_detail) |expected| {
            try std.testing.expectEqualStrings(expected, mapped.status_detail.?);
        } else {
            try std.testing.expect(mapped.status_detail == null);
        }
    }
}

test "terminal public wait ceiling maps to action-specific Core requests" {
    const alloc = std.testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(alloc);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const ctx: tool_dispatch.DispatchContext = .{
        .allocator = alloc,
        .workspace_root = "/tmp",
    };

    const start_decoded = try decode(
        .{ .allocator = alloc },
        "{\"action\":\"start\",\"command\":\"true\",\"return_when\":{\"kind\":\"exit\"},\"wait_ceiling_ms\":4000}",
    );
    switch (start_decoded) {
        .failure => |message| {
            defer alloc.free(message);
            return error.TestUnexpectedResult;
        },
        .input => |input| {
            defer input.deinit(alloc);
            const request = try semanticRequest(
                arena,
                ctx,
                &input.as(OwnedInput).parsed.value,
            );
            switch (request) {
                .start => |value| try std.testing.expectEqual(
                    @as(?u64, 4000),
                    value.wait_ceiling_ms,
                ),
                else => return error.TestUnexpectedResult,
            }
        },
    }

    const wait_decoded = try decode(
        .{ .allocator = alloc },
        "{\"action\":\"wait\",\"session_id\":\"terminal-a\",\"return_when\":{\"kind\":\"match\",\"pattern\":\"ready\"},\"wait_ceiling_ms\":5000}",
    );
    switch (wait_decoded) {
        .failure => |message| {
            defer alloc.free(message);
            return error.TestUnexpectedResult;
        },
        .input => |input| {
            defer input.deinit(alloc);
            const request = try semanticRequest(
                arena,
                ctx,
                &input.as(OwnedInput).parsed.value,
            );
            switch (request) {
                .wait => |value| try std.testing.expectEqual(
                    @as(u64, 5000),
                    value.safety_ceiling_ms,
                ),
                else => return error.TestUnexpectedResult,
            }
        },
    }
}

test "terminal public wait requires wait ceiling and rejects the removed field" {
    const alloc = std.testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(alloc);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const ctx: tool_dispatch.DispatchContext = .{
        .allocator = alloc,
        .workspace_root = "/tmp",
    };

    const missing_decoded = try decode(
        .{ .allocator = alloc },
        "{\"action\":\"wait\",\"session_id\":\"terminal-a\",\"return_when\":{\"kind\":\"exit\"}}",
    );
    switch (missing_decoded) {
        .failure => |message| {
            defer alloc.free(message);
            return error.TestUnexpectedResult;
        },
        .input => |input| {
            defer input.deinit(alloc);
            try std.testing.expectError(
                error.MissingWaitCeiling,
                semanticRequest(
                    arena,
                    ctx,
                    &input.as(OwnedInput).parsed.value,
                ),
            );
        },
    }

    const removed_decoded = try decode(
        .{ .allocator = alloc },
        "{\"action\":\"wait\",\"session_id\":\"terminal-a\",\"return_when\":{\"kind\":\"exit\"},\"safety_ceiling_ms\":5000}",
    );
    switch (removed_decoded) {
        .failure => |message| alloc.free(message),
        .input => |input| {
            input.deinit(alloc);
            return error.TestUnexpectedResult;
        },
    }
}

test "terminal public monitor builder projects schedules from the typed condition" {
    const monitor_core = @import("../../core/terminal/monitor.zig");
    const event_driven = try buildMonitorDefinition(.{
        .condition = .{
            .kind = .output_contains,
            .pattern = "ready",
        },
        .check_interval_ms = 1,
        .notify = .{ .kind = .on_match },
        .lifetime = .{ .kind = .until_match },
    });
    try std.testing.expect(event_driven.check_schedule == null);
    try monitor_core.validate_definition(event_driven);

    const polling_input = MonitorDefinitionInput{
        .condition = .{
            .kind = .tcp_ready,
            .host = "127.0.0.1",
            .port = 3000,
        },
        .notify = .{ .kind = .on_match },
        .lifetime = .{ .kind = .until_match },
    };
    try std.testing.expectError(
        error.MissingCheckSchedule,
        buildMonitorDefinition(polling_input),
    );

    var bounded_polling_input = polling_input;
    bounded_polling_input.check_interval_ms = monitor_core.minimum_schedule_ms;
    const bounded_polling = try buildMonitorDefinition(bounded_polling_input);
    try std.testing.expectEqual(
        monitor_core.minimum_schedule_ms,
        bounded_polling.check_schedule.?.interval_ms,
    );
    try monitor_core.validate_definition(bounded_polling);

    bounded_polling_input.check_interval_ms = monitor_core.minimum_schedule_ms - 1;
    const below_minimum = try buildMonitorDefinition(bounded_polling_input);
    try std.testing.expectError(
        error.InvalidSchedule,
        monitor_core.validate_definition(below_minimum),
    );
}

test "terminal initial add and update monitors share schedule projection" {
    const alloc = std.testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(alloc);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const input = MonitorDefinitionInput{
        .condition = .{
            .kind = .output_contains,
            .pattern = "ready",
        },
        .check_interval_ms = 1,
        .notify = .{ .kind = .on_match },
        .lifetime = .{ .kind = .until_match },
    };

    const initial = try buildMonitorDefinitions(arena, &.{input});
    try std.testing.expect(initial[0].check_schedule == null);

    const add = try buildMonitorOperation(.{
        .kind = .add,
        .definition = input,
    });
    switch (add) {
        .add => |definition| try std.testing.expect(definition.check_schedule == null),
        else => return error.TestUnexpectedResult,
    }

    const update = try buildMonitorOperation(.{
        .kind = .update,
        .monitor_id = "monitor-1",
        .definition = input,
    });
    switch (update) {
        .update => |value| try std.testing.expect(value.definition.check_schedule == null),
        else => return error.TestUnexpectedResult,
    }
}

test "terminal public list rejects lifecycle and projects supported filters" {
    const alloc = std.testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(alloc);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const ctx: tool_dispatch.DispatchContext = .{
        .allocator = alloc,
        .workspace_root = "/tmp",
    };

    const lifecycle_decoded = try decode(
        .{ .allocator = alloc },
        "{\"action\":\"list\",\"lifecycle\":\"running\"}",
    );
    switch (lifecycle_decoded) {
        .failure => |message| alloc.free(message),
        .input => |input| {
            input.deinit(alloc);
            return error.TestUnexpectedResult;
        },
    }

    const owner_catalog_decoded = try decode(
        .{ .allocator = alloc },
        "{\"action\":\"list\",\"backend\":\"native\"}",
    );
    switch (owner_catalog_decoded) {
        .failure => |message| {
            defer alloc.free(message);
            return error.TestUnexpectedResult;
        },
        .input => |input| {
            defer input.deinit(alloc);
            const request = try semanticRequest(
                arena,
                ctx,
                &input.as(OwnedInput).parsed.value,
            );
            try request.validate();
            switch (request) {
                .list => |filters| {
                    try std.testing.expect(filters.task_id == null);
                    try std.testing.expect(filters.workspace_root == null);
                    try std.testing.expect(filters.lifecycle == null);
                    try std.testing.expectEqual(
                        contracts.Backend.native,
                        filters.backend.?,
                    );
                },
                else => return error.TestUnexpectedResult,
            }
        },
    }

    const empty_decoded = try decode(
        .{ .allocator = alloc },
        "{\"action\":\"list\",\"task_id\":\"\",\"workspace_root\":\"\"}",
    );
    switch (empty_decoded) {
        .failure => |message| {
            defer alloc.free(message);
            return error.TestUnexpectedResult;
        },
        .input => |input| {
            defer input.deinit(alloc);
            const request = try semanticRequest(
                arena,
                ctx,
                &input.as(OwnedInput).parsed.value,
            );
            try request.validate();
            switch (request) {
                .list => |filters| {
                    try std.testing.expect(filters.task_id == null);
                    try std.testing.expect(filters.workspace_root == null);
                    try std.testing.expect(filters.lifecycle == null);
                },
                else => return error.TestUnexpectedResult,
            }
        },
    }

    const expected_workspace = try io_mod.realpathAlloc(alloc, "/tmp");
    defer alloc.free(expected_workspace);
    const filtered_decoded = try decode(
        .{ .allocator = alloc },
        "{\"action\":\"list\",\"task_id\":\"task-a\",\"workspace_root\":\"/tmp/.\"}",
    );
    switch (filtered_decoded) {
        .failure => |message| {
            defer alloc.free(message);
            return error.TestUnexpectedResult;
        },
        .input => |input| {
            defer input.deinit(alloc);
            const request = try semanticRequest(
                arena,
                ctx,
                &input.as(OwnedInput).parsed.value,
            );
            try request.validate();
            switch (request) {
                .list => |filters| {
                    try std.testing.expectEqualStrings("task-a", filters.task_id.?);
                    try std.testing.expectEqualStrings(
                        expected_workspace,
                        filters.workspace_root.?,
                    );
                },
                else => return error.TestUnexpectedResult,
            }
        },
    }

    const invalid_decoded = try decode(
        .{ .allocator = alloc },
        "{\"action\":\"list\",\"workspace_root\":\" \\t \"}",
    );
    switch (invalid_decoded) {
        .failure => |message| {
            defer alloc.free(message);
            return error.TestUnexpectedResult;
        },
        .input => |input| {
            defer input.deinit(alloc);
            try std.testing.expectError(
                error.InvalidPath,
                semanticRequest(
                    arena,
                    ctx,
                    &input.as(OwnedInput).parsed.value,
                ),
            );
        },
    }
}

test "terminal decoder and semantic validation reject malformed action input" {
    const alloc = std.testing.allocator;
    const malformed = try decode(.{ .allocator = alloc }, "{\"action\":\"bogus\"}");
    switch (malformed) {
        .input => |input| {
            input.deinit(alloc);
            return error.TestUnexpectedResult;
        },
        .failure => |message| alloc.free(message),
    }

    const decoded = try decode(.{ .allocator = alloc }, "{\"action\":\"write\",\"session_id\":\"terminal-a\"}");
    switch (decoded) {
        .failure => |message| {
            defer alloc.free(message);
            return error.TestUnexpectedResult;
        },
        .input => |input| {
            defer input.deinit(alloc);
            const reason = (try validate(.{
                .allocator = alloc,
                .workspace_root = "/tmp",
            }, input)) orelse return error.TestUnexpectedResult;
            defer alloc.free(reason);
            try std.testing.expect(std.mem.find(u8, reason, "InvalidWritePayload") != null);
        },
    }
}

test "terminal read-only classification is action exact" {
    const alloc = std.testing.allocator;
    inline for (.{
        .{ "{\"action\":\"read\"}", true },
        .{ "{\"action\":\"screen\"}", true },
        .{ "{\"action\":\"inspect\"}", true },
        .{ "{\"action\":\"inspect\",\"acknowledge_event_id\":1}", false },
        .{ "{\"action\":\"list\"}", true },
        .{ "{\"action\":\"write\"}", false },
    }) |case| {
        const decoded = try decode(.{ .allocator = alloc }, case[0]);
        switch (decoded) {
            .failure => |message| {
                defer alloc.free(message);
                return error.TestUnexpectedResult;
            },
            .input => |input| {
                defer input.deinit(alloc);
                try std.testing.expectEqual(case[1], readsOnly(input));
            },
        }
    }
}
