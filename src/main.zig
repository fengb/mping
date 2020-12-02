const std = @import("std");

//pub const io_mode = .evented;

fn rfc1071Checksum(data: []const u16) u16 {
    var result: u16 = 0;
    for (data) |d| {
        if (@addWithOverflow(u16, result, d, &result)) {
            result += 1;
        }
    }
    return result;
}

// From musl icmp.h
const IcmpHdr = extern struct {
    /// message type
    @"type": enum(u8) { ECHO_REPLY = 0, ECHO_REQUEST = 8, _ },
    /// type sub-code
    code: u8,
    checksum: u16,

    un: extern union {
        /// path mtu discovery
        echo: extern struct {
            id: u16,
            sequence: u16,
        },
        gateway: u32,
        frag: extern struct {
            __glibc_reserved: u16,
            mtu: u16,
        },
    },

    pub fn initEcho(id: u16, sequence: u16) IcmpHdr {
        var result = IcmpHdr{
            .@"type" = .ECHO_REQUEST,
            .code = 0,
            .checksum = undefined,
            .un = .{
                .echo = .{ .id = id, .sequence = sequence },
            },
        };
        result.recalcChecksum();
        return result;
    }

    pub fn recalcChecksum(self: *IcmpHdr) void {
        self.checksum = 0;
        self.checksum = rfc1071Checksum(std.mem.bytesAsSlice(u16, std.mem.asBytes(self)));
    }
};

pub fn main() anyerror!void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const fs = try icmpConnectTo(&gpa.allocator, "1.1.1.1");
    defer fs.close();

    const echo = IcmpHdr.initEcho(1, 2);
    std.debug.print("{} -> {}\n", .{ echo, echo.un.echo });

    const written = try fs.write(std.mem.asBytes(&echo));
    std.debug.assert(written == @sizeOf(IcmpHdr));

    std.debug.print("written: {} bytes\n", .{written});

    var buffer: [@sizeOf(IcmpHdr)]u8 = undefined;
    const read = try fs.read(&buffer);
    std.debug.assert(read == @sizeOf(IcmpHdr));
    std.debug.print("{}\n", .{buffer});
}

pub fn icmpConnectTo(allocator: *std.mem.Allocator, name: []const u8) !std.fs.File {
    const list = try std.net.getAddressList(allocator, name, 0);
    defer list.deinit();

    if (list.addrs.len == 0) return error.UnknownHostName;

    for (list.addrs) |addr| {
        return icmpConnectToAddress(addr) catch |err| switch (err) {
            error.ConnectionRefused => continue,
            else => return err,
        };
    }
    return error.ConnectionRefused;
}

pub fn icmpConnectToAddress(address: std.net.Address) !std.fs.File {
    const nonblock = if (std.io.is_async) std.os.SOCK_NONBLOCK else 0;
    const sock_flags = std.os.SOCK_DGRAM | nonblock |
        (if (std.builtin.os.tag == .windows) 0 else std.os.SOCK_CLOEXEC);
    const sockfd = try std.os.socket(address.any.family, sock_flags, std.os.IPPROTO_ICMP);
    errdefer std.os.closeSocket(sockfd);

    if (std.io.is_async) {
        const loop = std.event.Loop.instance orelse return error.WouldBlock;
        try loop.connect(sockfd, &address.any, address.getOsSockLen());
    } else {
        try std.os.connect(sockfd, &address.any, address.getOsSockLen());
    }

    return std.fs.File{ .handle = sockfd };
}
