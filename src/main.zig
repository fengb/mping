const std = @import("std");
const netx = @import("netx.zig");

pub const io_mode = .evented;

const Pingu = struct {
    source: union(enum) {
        none: void,
        ip: netx.Ipv4Host,
        iface: []const u8,
    },
    target: []const u8,
    socket: ?std.fs.File = none,
    reply_frame: @Frame(handleReplies),

    fn parse(raw: []const u8) !Pingu {
        return Pingu{
            .source = .none,
            .target = raw,
            .socket = null,
            .reply_frame = undefined,
        };
    }
};

var short_pid: u16 = undefined;

pub fn main() anyerror!u8 {
    short_pid = @truncate(u16, std.math.absCast(std.os.system.getpid()));

    var gpa = std.heap.GeneralPurposeAllocator(.{}){};

    const args = try std.process.argsAlloc(&gpa.allocator);
    defer std.process.argsFree(&gpa.allocator, args);

    // TODO: parse other args
    const hosts = args[1..];

    if (hosts.len == 0) {
        std.debug.print("Usage: mping host [host2 ...]\n", .{});
        return 1;
    }

    const pingus = try gpa.allocator.alloc(Pingu, hosts.len);
    defer gpa.allocator.free(pingus);

    for (hosts) |host, i| {
        pingus[i] = try Pingu.parse(host);
    }
    defer {
        for (hosts) |host| {
            if (host.socket) |sock| {
                sock.close();
            }
        }
    }

    var seq: usize = 0;
    while (true) : (seq +%= 1) {
        var sleep_frame = async std.time.sleep(std.time.ns_per_s);
        defer await sleep_frame;

        const echo = netx.Icmp.initEcho(short_pid, @truncate(u16, seq), now());

        for (pingus) |*pingu| {
            send(&gpa.allocator, pingu, echo) catch |err| {
                std.debug.print("{} {} cannot connect: {}\n", .{ seq, pingu.target, err });
                if (pingu.socket) |socket| {
                    // TODO: shutdown before closing
                    socket.close();
                    pingu.socket = null;
                    // TODO: ensure the listener is properly destroyed
                    // await pingu.reply_frame catch |e| {
                    //     std.debug.print("Done! {}\n", .{e});
                    // };
                }
            };
        }
    }
}

pub fn send(allocator: *std.mem.Allocator, pingu: *Pingu, echo: netx.Icmp) !void {
    if (pingu.socket == null) {
        const socket = try netx.icmpConnectTo(allocator, pingu.target);
        pingu.socket = socket;
        pingu.reply_frame = async handleReplies(socket);
    }

    const written = try pingu.socket.?.write(std.mem.asBytes(&echo));
    std.debug.assert(written == @sizeOf(netx.Icmp));
}

pub fn handleReplies(fs: std.fs.File) !void {
    var buffer: [0x100]u8 align(4) = undefined;
    while (true) {
        const read = try fs.read(&buffer);

        const ip_header = @ptrCast(*const netx.IpHeader, &buffer);
        const reply = @ptrCast(*const netx.Icmp, buffer[@sizeOf(netx.IpHeader)..]);

        if (!reply.checksumValid() or reply.un.echo.id() != short_pid) {
            continue;
        }

        const sent = reply.data.getEchoTime();
        const received = now();

        const diff_us: u64 = us(received) - us(sent);

        std.debug.print("{} {} {}.{}ms\n", .{ reply.un.echo.sequence(), ip_header.src_addr, diff_us / 1000, diff_us % 1000 });
    }
}

fn us(time: std.os.timeval) u64 {
    return @intCast(u64, time.tv_sec) * 1000000 + @intCast(u64, time.tv_usec);
}

fn now() std.os.timeval {
    var result: std.os.timeval = undefined;
    std.os.gettimeofday(&result, null);
    return result;
}
