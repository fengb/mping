//! Low level network extension functions

const std = @import("std");

pub const IpHeader = extern struct {
    ver_ihl: u8,
    tos: u8,
    total_length: u16,
    id: u16,
    flags_fo: u16,
    ttl: u8,
    protocol: u8,
    checksum: u16,
    src_addr: Ipv4Host,
    dst_addr: Ipv4Host,

    const Ipv4Host = extern struct {
        bytes: [4]u8,

        pub fn format(
            self: Ipv4Host,
            comptime fmt: []const u8,
            options: std.fmt.FormatOptions,
            writer: anytype,
        ) !void {
            try writer.print("{}.{}.{}.{}", .{
                self.bytes[0],
                self.bytes[1],
                self.bytes[2],
                self.bytes[3],
            });
        }
    };
};

pub const Icmp = extern struct {
    /// message type
    @"type": enum(u8) { ECHO_REPLY = 0, ECHO_REQUEST = 8, _ },
    /// type sub-code
    code: u8,
    checksum: u16,

    un: extern union {
        /// path mtu discovery
        echo: extern struct {
            id_be: u16,
            sequence_be: u16,

            pub fn id(self: @This()) u16 {
                return std.mem.toNative(u16, self.id_be, .Big);
            }

            pub fn sequence(self: @This()) u16 {
                return std.mem.toNative(u16, self.sequence_be, .Big);
            }
        },
        gateway: u32,
        frag: extern struct {
            _reserved: u16,
            mtu: u16,
        },
    },

    data: extern struct {
        bytes: [56]u8 = [_]u8{0} ** 56,

        pub fn setEchoTime(self: *@This(), time: std.os.timeval) void {
            std.mem.writeIntBig(u32, self.bytes[0..4], @intCast(u32, time.tv_sec));
            std.mem.writeIntBig(i32, self.bytes[4..8], @intCast(i32, time.tv_usec));
        }

        pub fn getEchoTime(self: @This()) std.os.timeval {
            var result: std.os.timeval = undefined;
            result.tv_sec = std.mem.readIntBig(u32, self.bytes[0..4]);
            result.tv_usec = std.mem.readIntBig(i32, self.bytes[4..8]);
            return result;
        }
    },

    pub fn initEcho(id: u16, sequence: u16, time: std.os.timeval) Icmp {
        var result = Icmp{
            .@"type" = .ECHO_REQUEST,
            .code = 0,
            .checksum = undefined,
            .un = .{
                .echo = .{
                    .id_be = std.mem.nativeTo(u16, id, .Big),
                    .sequence_be = std.mem.nativeTo(u16, sequence, .Big),
                },
            },
            .data = .{},
        };
        result.data.setEchoTime(time);
        result.recalcChecksum();
        return result;
    }

    pub fn recalcChecksum(self: *Icmp) void {
        self.checksum = 0;
        self.checksum = rfc1071Checksum(std.mem.asBytes(self));
    }

    pub fn checksumValid(self: Icmp) bool {
        var copy = self;
        copy.checksum = 0;
        return self.checksum == rfc1071Checksum(std.mem.asBytes(&copy));
    }
};

pub fn rfc1071Checksum(bytes: []const u8) u16 {
    const slice = std.mem.bytesAsSlice(u16, bytes);

    var sum: u16 = 0;
    for (slice) |d| {
        if (@addWithOverflow(u16, sum, d, &sum)) {
            sum += 1;
        }
    }
    return ~sum;
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
