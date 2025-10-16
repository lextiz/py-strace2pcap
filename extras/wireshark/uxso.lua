-- Wireshark dissector for UXSO (AF_UNIX strace events in DLT_USER0)

local uxso_proto = Proto("UXSO", "UNIX Socket Observation")

local f_magic = ProtoField.string("uxso.magic", "Magic")
local f_version = ProtoField.uint8("uxso.version", "Version")
local f_sock_type = ProtoField.uint8("uxso.sock_type", "Socket Type", base.DEC, {[1] = "STREAM", [2] = "DGRAM"})
local f_direction = ProtoField.uint8("uxso.direction", "Direction", base.DEC, {[0] = "Unknown", [1] = "write", [2] = "read"})
local f_flags = ProtoField.uint8("uxso.flags", "Flags", base.HEX, {[0x1] = "path", [0x2] = "peer_path"})
local f_pid = ProtoField.uint32("uxso.pid", "PID")
local f_fd = ProtoField.uint32("uxso.fd", "FD")
local f_inode = ProtoField.uint32("uxso.inode", "Inode")
local f_stream_id = ProtoField.uint32("uxso.stream_id", "Stream ID")
local f_payload_len = ProtoField.uint32("uxso.payload_len", "Payload Length")
local f_path = ProtoField.string("uxso.path", "Path")
local f_peer_path = ProtoField.string("uxso.peer_path", "Peer Path")
local f_payload = ProtoField.bytes("uxso.payload", "Payload")

uxso_proto.fields = { f_magic, f_version, f_sock_type, f_direction, f_flags,
    f_pid, f_fd, f_inode, f_stream_id, f_payload_len, f_path, f_peer_path,
    f_payload }

function uxso_proto.dissector(buffer, pinfo, tree)
    if buffer:len() < 24 then return end
    local magic = buffer(0, 4):string()
    if magic ~= "UXSO" then return end
    local version = buffer(4, 1):uint()
    if version ~= 1 then return end

    pinfo.cols.protocol = "UXSO"

    local subtree = tree:add(uxso_proto, buffer(), "UNIX Socket Observation")
    subtree:add(f_magic, buffer(0, 4))
    subtree:add(f_version, buffer(4, 1))
    subtree:add(f_sock_type, buffer(5, 1))
    subtree:add(f_direction, buffer(6, 1))
    subtree:add(f_flags, buffer(7, 1))
    subtree:add(f_pid, buffer(8, 4))
    subtree:add(f_fd, buffer(12, 4))
    subtree:add(f_inode, buffer(16, 4))
    subtree:add(f_stream_id, buffer(20, 4))
    subtree:add(f_payload_len, buffer(24, 4))

    local cursor = 28
    local flags = buffer(7, 1):uint()
    if bit32.band(flags, 0x01) ~= 0 then
        local zero = buffer:range(cursor):stringz():len()
        subtree:add(f_path, buffer(cursor, zero))
        cursor = cursor + zero + 1
    end
    if bit32.band(flags, 0x02) ~= 0 then
        local zero = buffer:range(cursor):stringz():len()
        subtree:add(f_peer_path, buffer(cursor, zero))
        cursor = cursor + zero + 1
    end

    local payload_len = buffer(24, 4):uint()
    if payload_len > 0 and cursor + payload_len <= buffer:len() then
        subtree:add(f_payload, buffer(cursor, payload_len))
    end
end

register_postdissector(uxso_proto)
