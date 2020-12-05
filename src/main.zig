const std = @import("std");
const netx = @import("netx.zig");

pub const io_mode = .evented;

var echo_id: u16 = undefined;

pub fn main() anyerror!u8 {
    echo_id = @truncate(u16, std.math.absCast(std.os.system.getpid()));

    var gpa = std.heap.GeneralPurposeAllocator(.{}){};

    const args = try std.process.argsAlloc(&gpa.allocator);
    defer std.process.argsFree(&gpa.allocator, args);

    const ips = args[1..];

    if (ips.len == 0) {
        std.debug.print("Usage: mping host [host2 ...]\n", .{});
        return 1;
    }

    const sockets = try gpa.allocator.alloc(?std.fs.File, ips.len);
    defer gpa.allocator.free(sockets);

    std.mem.set(?std.fs.File, sockets, null);
    defer {
        for (sockets) |socket| {
            if (socket) |sock| {
                sock.close();
            }
        }
    }

    const reply_frames = try gpa.allocator.alloc(@Frame(handleReplies), sockets.len);
    defer gpa.allocator.free(reply_frames);

    var seq: usize = 0;
    while (true) : (seq +%= 1) {
        var sleep_frame = async std.time.sleep(std.time.ns_per_s);
        defer await sleep_frame;

        const time = now();
        const echo = netx.Icmp.initEcho(echo_id, @truncate(u16, seq), time);

        for (ips) |ip, i| {
            if (sockets[i] == null) {
                if (netx.icmpConnectTo(&gpa.allocator, ip)) |socket| {
                    sockets[i] = socket;
                    reply_frames[i] = async handleReplies(socket);
                } else |err| {
                    std.debug.print("{} {} cannot connect: {}\n", .{ seq, ip, err });
                    continue;
                }
            }

            if (sockets[i].?.write(std.mem.asBytes(&echo))) |written| {
                std.debug.assert(written == @sizeOf(netx.Icmp));
            } else |err| {
                // TODO: shutdown before closing
                std.debug.print("{} {} cannot connect: {}\n", .{ seq, ip, err });
                sockets[i].?.close();
                sockets[i] = null;
                // TODO: ensure the listener is properly destroyed
                // await reply_frames[i] catch |e| {
                //     std.debug.print("Done! {}\n", .{e});
                // };
            }
        }
    }
}

pub fn handleReplies(fs: std.fs.File) !void {
    var buffer: [0x100]u8 align(4) = undefined;
    while (true) {
        const read = try fs.read(&buffer);

        const ip_header = @ptrCast(*const netx.IpHeader, &buffer);
        const reply = @ptrCast(*const netx.Icmp, buffer[@sizeOf(netx.IpHeader)..]);

        if (!reply.checksumValid() or reply.un.echo.id() != echo_id) {
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
