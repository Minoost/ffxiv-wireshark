-- create protocol
ffxiv_proto = Proto("ffxiv", "FFXIV", "FINAL FANTASY XIV: Heavensward Protocol")

-- generic header offset
local OFFSET_HEADER_TIMESTAMP         = 0x10 -- unixtime in millisecond
local OFFSET_HEADER_FRAME_LEN         = 0x18 -- frame length in bytes (includes 40bytes header!)
local OFFSET_HEADER_UNKNOWN1          = 0x1C
-- message header offset
local OFFSET_HEADER_MSG_COUNT         = 0x1E -- number of messages in packet frame
local OFFSET_HEADER_UNKNOWN2          = 0x20
local OFFSET_HEADER_MSG_COMPRESSED    = 0x21 -- if 1, payload is compressed with deflate

-- field display
local MESSAGE_TYPE = {
    [3] = "Normal?",
    [7] = "Ping",
    [8] = "Pong",
}

-- Protocol fields
local pfield = {
    header_unknown0			= ProtoField.bytes("ffxiv.header.unknown0", "Unknown0"),
    header_unknown1 	    = ProtoField.uint16("ffxiv.header.unknown1", "Unknown1"),
    header_unknown2 		= ProtoField.bool("ffxiv.header.unknown2", "Unknown2"),
    header_timestamp 		= ProtoField.absolute_time("ffxiv.header.timestamp", "Frame Timestamp"),
    header_frame_len 	    = ProtoField.uint32("ffxiv.header.length", "Frame Length"),
    header_msg_count 		= ProtoField.uint16("ffxiv.header.msg_count", "Message Count"),
    header_msg_compressed	= ProtoField.bool("ffxiv.header.compressed", "Payload is Compressed?"),

    -- messages
    subheader_msg_len       = ProtoField.uint32("ffxiv.msg.length", "Message Length"),
    subheader_msg_type      = ProtoField.uint16("ffxiv.msg.type", "Message Type", nil, MESSAGE_TYPE),
}
ffxiv_proto.fields = pfield -- register field to protocol

function ffxiv_proto.dissector(buf, pinfo, tree)
    -- not enough data (not even frame header!)
    if buf:len() < 40 then
        return
    end

    pinfo.cols.protocol = "FFXIV" -- set protocol col name

    local ptree = tree:add(ffxiv_proto, buf(), "FINAL FANTASY XIV: Heavensward")

    -- add unknown fields
    local utree = ptree:add(buf(0,0), "Unknown Fields")

    local unknown0 = buf(0, 16)
    local unknown1 = buf(OFFSET_HEADER_UNKNOWN1, 2)
    local unknown2 = buf(OFFSET_HEADER_UNKNOWN2, 1)
    utree:add   (pfield.header_unknown0, unknown0)
    utree:add_le(pfield.header_unknown1, unknown1)
    utree:add_le(pfield.header_unknown2, unknown2)

    -- dissect header
    local timestamp 	= buf(OFFSET_HEADER_TIMESTAMP, 8)
    local timestamp_nst = nstime_from_unix_msec(timestamp:le_uint64())
    local frame_len 	= buf(OFFSET_HEADER_FRAME_LEN, 4)
    local msg_count 	= buf(OFFSET_HEADER_MSG_COUNT, 2)
    local compressed	= buf(OFFSET_HEADER_MSG_COMPRESSED, 1)

    ptree:add   (pfield.header_timestamp, timestamp, timestamp_nst)
    ptree:add_le(pfield.header_frame_len, frame_len)
    ptree:add   (pfield.header_msg_compressed, compressed)
    ptree:add_le(pfield.header_msg_count, msg_count)

    -- dissect messages
    local mbuf = buf(40)
    local mtree = ptree:add(mbuf, "Messages")
    -- TODO: dissect messages!

    -- handle desegment
    if frame_len:le_uint() > buf:len() then
        pinfo.desegment_len = frame_len:le_uint() - buf:len()
    end

    return frame_len:le_uint()
end

-- # Heuristic
--     This plugin attempt to find a packet that follows FFXIV protocol
--     convention and dissect it automatically.
--
--     This is done by:
--         1. check first 16 bytes of packet starts with predefined value
--         2. or length of tcp packet segment has a same value as
--         frame header length does
--
-- # Signature(16 bytes) disassembly:
-- In heavensward, first 16 bytes from header are hardcoded in subroutine
-- (or atleast inlined for optimization by compiler)
--
-- 01582ACD | C6 02 52                 | mov byte ptr ds:[edx],52
-- 01582AD0 | 8B 46 08                 | mov eax,dword ptr ds:[esi+8]
-- 01582AD3 | C6 40 01 52              | mov byte ptr ds:[eax+1],52
-- 01582AD7 | 8B 56 08                 | mov edx,dword ptr ds:[esi+8]
-- 01582ADA | C6 42 02 A0              | mov byte ptr ds:[edx+2],A0
-- 01582ADE | 8B 46 08                 | mov eax,dword ptr ds:[esi+8]
-- 01582AE1 | C6 40 03 41              | mov byte ptr ds:[eax+3],41
-- 01582AE5 | 8B 56 08                 | mov edx,dword ptr ds:[esi+8]
-- 01582AE8 | C6 42 04 FF              | mov byte ptr ds:[edx+4],FF
-- 01582AEC | 8B 46 08                 | mov eax,dword ptr ds:[esi+8]
-- 01582AEF | C6 40 05 5D              | mov byte ptr ds:[eax+5],5D
-- 01582AF3 | 8B 56 08                 | mov edx,dword ptr ds:[esi+8]
-- 01582AF6 | C6 42 06 46              | mov byte ptr ds:[edx+6],46
-- 01582AFA | 8B 46 08                 | mov eax,dword ptr ds:[esi+8]
-- 01582AFD | C6 40 07 E2              | mov byte ptr ds:[eax+7],E2
-- 01582B01 | 8B 56 08                 | mov edx,dword ptr ds:[esi+8]
-- 01582B04 | C6 42 08 7F              | mov byte ptr ds:[edx+8],7F
-- 01582B08 | 8B 46 08                 | mov eax,dword ptr ds:[esi+8]
-- 01582B0B | C6 40 09 2A              | mov byte ptr ds:[eax+9],2A
-- 01582B0F | 8B 56 08                 | mov edx,dword ptr ds:[esi+8]
-- 01582B12 | C6 42 0A 64              | mov byte ptr ds:[edx+A],64
-- 01582B16 | 8B 46 08                 | mov eax,dword ptr ds:[esi+8]
-- 01582B19 | C6 40 0B 4D              | mov byte ptr ds:[eax+B],4D
-- 01582B1D | 8B 56 08                 | mov edx,dword ptr ds:[esi+8]
-- 01582B20 | C6 42 0C 7B              | mov byte ptr ds:[edx+C],7B
-- 01582B24 | 8B 46 08                 | mov eax,dword ptr ds:[esi+8]
-- 01582B27 | C6 40 0D 99              | mov byte ptr ds:[eax+D],99
-- 01582B2B | 8B 56 08                 | mov edx,dword ptr ds:[esi+8]
-- 01582B2E | C6 42 0E C4              | mov byte ptr ds:[edx+E],C4
-- 01582B32 | 8B 46 08                 | mov eax,dword ptr ds:[esi+8]
-- 01582B35 | 8B 55 FC                 | mov edx,dword ptr ss:[ebp-4]
-- 01582B38 | C6 40 0F 75              | mov byte ptr ds:[eax+F],75

-- register heuristic
ffxiv_proto:register_heuristic("tcp", function (buf, pinfo, tree)
    local result = is_ffxiv_packet(buf)
    if result then
        -- ffxiv packet detected, so let's dissect it!
        ffxiv_proto.dissector(buf, pinfo, tree)

        -- stick with ffxiv protocol for this addr:port
        pinfo.conversation = ffxiv_proto
    end
    return result
end)

-- returns true if buf follows ffxiv packet convention, false otherwise.
function is_ffxiv_packet(buf)
    -- see if packet has enough room for frame header
    -- if not, this packet is not for us
    if buf:len() < 40 then
        return false
    end

    -- if first 16 bytes are equal to predefined value, (52 52..)
    -- this our packet!
    local sig = buf(0, 16)
    local sig_expected = ByteArray.new("52 52 A0 41 FF 5D 46 E2 7F 2A 64 4D 7B 99 C4 75")
    if sig:tvb() == sig_expected:tvb() then
        return true
    end

    -- check frame length == packet length
    local frame_len = buf(OFFSET_HEADER_FRAME_LEN, 4):uint()
    if frame_len == buf:reported_len() then
        return true
    end

    -- not a ffxiv packet :<
    return false
end

-- takes uint64 timestamp as a unix epoch in millisecond,
-- convert it to NSTime
function nstime_from_unix_msec(timestamp)
    local ts_sec = (timestamp / 1000):tonumber()
    local ts_nano = (timestamp % 1000):tonumber() * 1000000
    return NSTime.new(ts_sec, ts_nano)
end

-- register it for tcp port 42424 (algo project)
local tcp_table = DissectorTable.get("tcp.port")
tcp_table:add(42424, ffxiv_proto)
