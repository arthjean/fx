const std = @import("std");
const io_mod = @import("../shared/io.zig");
const mcp_access = @import("../mcp/access_policy.zig");
const mcp_contract = @import("../mcp/mcp_contract.zig");
const elicitation = @import("../mcp/elicitation.zig");
const mcp_health = @import("../mcp/health.zig");
const mcp_runtime = @import("../mcp/mcp_runtime.zig");
const context_limits = @import("../config/context_limits.zig");
const tool_advertisement = @import("../tooling/tool_advertisement.zig");
const tool_dispatch = @import("../tooling/tool_dispatch.zig");
const tool_mcp_runtime = @import("../tooling/tool_mcp_runtime.zig");
const tool_set = @import("../tooling/tool_set.zig");
const types = @import("../shared/types.zig");

const Allocator = std.mem.Allocator;

pub const Lease = struct {
    runtime: *mcp_runtime.McpRuntime,

    pub fn deinit(self: *Lease) void {
        self.runtime.releaseUse();
        self.* = undefined;
    }
};

pub const ReloadOutcome = union(enum) {
    published: struct {
        generation: ?u64,
        health: mcp_health.StartupDecision,
    },
    retained_required_failure: []u8,

    pub fn deinit(self: *ReloadOutcome, alloc: Allocator) void {
        switch (self.*) {
            .published => {},
            .retained_required_failure => |message| alloc.free(message),
        }
        self.* = undefined;
    }
};

/// Owns the native profile MCP runtime. All transport work and retirement happen
/// after releasing this state lock; the lock protects only pointer publication.
pub const State = struct {
    lock: std.Io.RwLock = .init,
    runtime: ?*mcp_runtime.McpRuntime = null,

    pub fn installInitial(self: *State, runtime: ?*mcp_runtime.McpRuntime) void {
        std.debug.assert(self.runtime == null);
        self.runtime = runtime;
    }

    pub fn startDiscovery(self: *State, registry: tool_dispatch.Registry) void {
        var lease = self.acquire() orelse return;
        defer lease.deinit();
        lease.runtime.startDiscovery(registry);
    }

    pub fn acquire(self: *State) ?Lease {
        self.lock.lockSharedUncancelable(io_mod.getIo());
        const runtime = self.runtime orelse {
            self.lock.unlockShared(io_mod.getIo());
            return null;
        };
        if (!runtime.acquireUse()) {
            self.lock.unlockShared(io_mod.getIo());
            return null;
        }
        self.lock.unlockShared(io_mod.getIo());
        return .{ .runtime = runtime };
    }

    pub fn hasTool(self: *State, name: []const u8, access: tool_mcp_runtime.Access) bool {
        var lease = self.acquire() orelse return false;
        defer lease.deinit();
        return lease.runtime.hasToolWithAccess(name, access);
    }

    pub fn validateTool(
        self: *State,
        arena: Allocator,
        name: []const u8,
        arguments_json: []const u8,
        access: tool_mcp_runtime.Access,
    ) !tool_mcp_runtime.ValidationResult {
        var lease = self.acquire() orelse return .not_available;
        defer lease.deinit();
        return lease.runtime.validateToolArgumentsByNameWithAccess(
            arena,
            name,
            arguments_json,
            access,
        );
    }

    pub fn callTool(
        self: *State,
        arena: Allocator,
        name: []const u8,
        arguments_json: []const u8,
        max_tool_result_bytes: usize,
        options: tool_mcp_runtime.CallOptions,
    ) !?tool_mcp_runtime.CallResult {
        var lease = self.acquire() orelse return null;
        defer lease.deinit();
        return lease.runtime.callToolByNameWithOptions(
            arena,
            name,
            arguments_json,
            max_tool_result_bytes,
            options,
        );
    }

    pub fn searchTools(
        self: *State,
        arena: Allocator,
        query: []const u8,
        limit: usize,
        permission_rules: types.PermissionRuleSet,
        limits: context_limits.Values,
        access: tool_mcp_runtime.Access,
    ) !tool_mcp_runtime.SearchResult {
        var lease = self.acquire() orelse
            return .{ .model_output = try arena.dupe(u8, "{\"tools\":[],\"count\":0}") };
        defer lease.deinit();
        return lease.runtime.searchTools(arena, query, limit, permission_rules, limits, access);
    }

    pub fn toolSchema(
        self: *State,
        arena: Allocator,
        name: []const u8,
        permission_rules: types.PermissionRuleSet,
        limits: context_limits.Values,
        access: tool_mcp_runtime.Access,
    ) !?tool_mcp_runtime.ToolSchemaResult {
        var lease = self.acquire() orelse return null;
        defer lease.deinit();
        return lease.runtime.toolSchemaJsonByNameWithAccess(
            arena,
            name,
            permission_rules,
            limits,
            access,
        );
    }

    pub fn renderHealth(self: *State, alloc: Allocator) ![]u8 {
        var lease = self.acquire() orelse return alloc.dupe(u8, "No MCP servers configured.\n");
        defer lease.deinit();
        return lease.runtime.listServersAndTools(alloc);
    }

    pub fn snapshotToolNames(
        self: *State,
        alloc: Allocator,
        permission_rules: types.PermissionRuleSet,
    ) ![][]u8 {
        var lease = self.acquire() orelse return alloc.alloc([]u8, 0);
        defer lease.deinit();
        return lease.runtime.snapshotToolNames(alloc, permission_rules);
    }

    pub fn snapshotAccessView(
        self: *State,
        alloc: Allocator,
        owner_id: []const u8,
        parent_id: []const u8,
        permission_rules: types.PermissionRuleSet,
        features_visible: bool,
    ) !?mcp_access.View {
        var lease = self.acquire() orelse return null;
        defer lease.deinit();
        const view = try lease.runtime.snapshotAccessView(
            alloc,
            owner_id,
            parent_id,
            permission_rules,
            features_visible,
        );
        return view;
    }

    pub fn waitForRequired(
        self: *State,
        alloc: Allocator,
        cancel_flag: ?*std.atomic.Value(bool),
        captured_at_ms: u64,
    ) !?[]u8 {
        var lease = self.acquire() orelse return null;
        defer lease.deinit();
        try lease.runtime.waitForDiscovery(cancel_flag);
        return lease.runtime.requiredStartupFailure(alloc, captured_at_ms);
    }

    pub fn reload(
        self: *State,
        alloc: Allocator,
        elicitation_capabilities: elicitation.Capabilities,
        loader: mcp_runtime.LoadRuntimeFn,
        registry: tool_dispatch.Registry,
        captured_at_ms: u64,
    ) !ReloadOutcome {
        const candidate = try loader(alloc, elicitation_capabilities);
        var candidate_owned = candidate != null;
        errdefer if (candidate_owned) destroyRuntime(alloc, candidate.?);

        const decision: mcp_health.StartupDecision = if (candidate) |runtime| decision: {
            runtime.connectAll(registry);
            const value = try runtime.startupDecision(alloc, captured_at_ms);
            if (!mcp_health.publishCandidateForDecision(value)) {
                const failure = (try runtime.requiredStartupFailure(alloc, captured_at_ms)) orelse
                    try alloc.dupe(u8, "A required MCP server is unavailable.");
                destroyRuntime(alloc, runtime);
                candidate_owned = false;
                return .{ .retained_required_failure = failure };
            }
            break :decision value;
        } else .ready;

        self.lock.lockUncancelable(io_mod.getIo());
        const previous = self.runtime;
        self.runtime = candidate;
        self.lock.unlock(io_mod.getIo());
        candidate_owned = false;

        if (previous) |runtime| destroyRuntime(alloc, runtime);
        return .{ .published = .{
            .generation = if (candidate) |runtime| runtime.generation else null,
            .health = decision,
        } };
    }

    pub fn deinit(self: *State, alloc: Allocator) void {
        self.lock.lockUncancelable(io_mod.getIo());
        const previous = self.runtime;
        self.runtime = null;
        self.lock.unlock(io_mod.getIo());
        if (previous) |runtime| destroyRuntime(alloc, runtime);
        self.* = .{};
    }
};

pub fn buildModelToolProjection(
    state: *State,
    alloc: Allocator,
    advertisement_set: tool_set.ToolSet,
    options: tool_advertisement.Options,
) !tool_advertisement.EffectiveToolProjection {
    var lease = state.acquire();
    defer if (lease) |*active| active.deinit();
    var effective = options;
    effective.mcp_runtime = if (lease) |active| active.runtime else null;
    return tool_advertisement.buildModelToolProjectionForSet(
        alloc,
        advertisement_set,
        effective,
    );
}

fn destroyRuntime(alloc: Allocator, runtime: *mcp_runtime.McpRuntime) void {
    runtime.retireAndWait();
    runtime.deinit();
    alloc.destroy(runtime);
}

const TestReloadMode = enum {
    parse_failure,
    required_disabled,
    optional_failed,
    empty,
};

var test_reload_mode: TestReloadMode = .empty;

fn loadTestReloadRuntime(
    alloc: Allocator,
    _: elicitation.Capabilities,
) !?*mcp_runtime.McpRuntime {
    switch (test_reload_mode) {
        .parse_failure => return error.McpConfigInvalidJson,
        .empty => return null,
        .required_disabled, .optional_failed => {},
    }
    const runtime = try alloc.create(mcp_runtime.McpRuntime);
    errdefer alloc.destroy(runtime);
    runtime.* = mcp_runtime.McpRuntime.init(alloc);
    errdefer runtime.deinit();
    const name = try alloc.dupe(u8, "candidate");
    errdefer alloc.free(name);
    const command = try alloc.dupe(
        u8,
        if (test_reload_mode == .optional_failed) "__fx_missing_mcp_executable__" else "disabled",
    );
    errdefer alloc.free(command);
    const config = mcp_contract.McpServerConfig{
        .name = name,
        .command = command,
        .enabled = test_reload_mode == .optional_failed,
        .required = test_reload_mode == .required_disabled,
    };
    try runtime.addServer(config);
    return runtime;
}

test "transactional reload retains old runtime and publishes only accepted candidates" {
    const alloc = std.testing.allocator;
    var state: State = .{};
    defer state.deinit(alloc);
    const original = try alloc.create(mcp_runtime.McpRuntime);
    original.* = mcp_runtime.McpRuntime.init(alloc);
    const original_generation = original.generation;
    state.installInitial(original);

    test_reload_mode = .parse_failure;
    try std.testing.expectError(
        error.McpConfigInvalidJson,
        state.reload(alloc, .{}, loadTestReloadRuntime, .{}, 10),
    );
    {
        var lease = state.acquire() orelse return error.TestUnexpectedResult;
        defer lease.deinit();
        try std.testing.expectEqual(original_generation, lease.runtime.generation);
    }

    test_reload_mode = .required_disabled;
    var rejected = try state.reload(alloc, .{}, loadTestReloadRuntime, .{}, 20);
    defer rejected.deinit(alloc);
    switch (rejected) {
        .retained_required_failure => |failure| {
            try std.testing.expect(std.mem.find(u8, failure, "candidate") != null);
            try std.testing.expect(std.mem.find(u8, failure, "required") != null);
        },
        .published => return error.TestUnexpectedResult,
    }
    {
        var lease = state.acquire() orelse return error.TestUnexpectedResult;
        defer lease.deinit();
        try std.testing.expectEqual(original_generation, lease.runtime.generation);
    }

    test_reload_mode = .optional_failed;
    var degraded = try state.reload(alloc, .{}, loadTestReloadRuntime, .{}, 30);
    defer degraded.deinit(alloc);
    switch (degraded) {
        .published => |published| {
            try std.testing.expectEqual(mcp_health.StartupDecision.degraded, published.health);
            try std.testing.expect(published.generation.? != original_generation);
        },
        .retained_required_failure => return error.TestUnexpectedResult,
    }

    test_reload_mode = .empty;
    var empty = try state.reload(alloc, .{}, loadTestReloadRuntime, .{}, 40);
    defer empty.deinit(alloc);
    switch (empty) {
        .published => |published| {
            try std.testing.expectEqual(mcp_health.StartupDecision.ready, published.health);
            try std.testing.expect(published.generation == null);
        },
        .retained_required_failure => return error.TestUnexpectedResult,
    }
    try std.testing.expect(state.acquire() == null);
}
