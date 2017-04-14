-- Protocol fields
local pfield = {
    header_unknown0			= ProtoField.bytes("ffxiv.header.unknown0", "Unknown0"),
    header_timestamp 		= ProtoField.absolute_time("ffxiv.header.timestamp", "Timestamp"),
    header_len 				= ProtoField.uint32("ffxiv.header.len", "Frame Length"),
    header_unknown_count 	= ProtoField.uint16("ffxiv.header.unknown1", "Unknown1"),
    header_msg_count 		= ProtoField.uint16("ffxiv.header.msg_count", "Message Count"),
    header_unknown2 		= ProtoField.bool("ffxiv.header.unknown2", "Unknown2"),
    header_is_compressed	= ProtoField.bool("ffxiv.header.compressed", "Payload is compressed?")
}

-- frame header offsets
local offset = {
    header_timestamp = 0x10,
    header_length = 0x18,
    header_unknown_type1 = 0x1C,
    header_msg_count = 0x1E,
    header_unknown_type2 = 0x20,
    header_is_compressed = 0x21,
}

local function init()
    xiv_proto = Proto("ffxiv", "FFXIV", "FINAL FANTASY XIV: Heavensward Protocol")
    xiv_proto.fields = pfield
    xiv_proto.dissector = dissect_packet

    -- register a dissector
    local tcp_table = DissectorTable.get("tcp.port")
    tcp_table:add(42424, xiv_proto)
end

function dissect_packet(buf, pinfo, tree)
    -- not enough data (not even frame header!)
    if buf:len() < 40 then
        return
    end

    -- add tree and set protocol name as FFXIV
    local ptree = tree:add(xiv_proto, buf(), "FINAL FANTASY XIV")
    pinfo.cols.protocol = "FFXIV"

    -- dissect header
    local hbuf  = buf(0, 40)
    local htree = ptree:add(hbuf, "Frame header")
    local flen  = dissect_header(hbuf, pinfo, htree)

    -- dissect messages
    local mbuf  = buf(40)
    local mtree = ptree:add(mbuf, "Messages")
    dissect_messages(mbuf, pinfo, mtree)

    -- desegment
    if flen:le_uint() > buf:reported_len() then
        pinfo.desegment_len = flen:le_uint() - buf:reported_len()
    end

    -- set length based on header read
    return flen:le_uint()
end

-- dissect header then returns frame length
function dissect_header(buf, pinfo, tree)
    -- direct vals
    local unknown0 		= buf(0, 16)
    local timestamp 	= buf(offset.header_timestamp, 8)
    local header_len 	= buf(offset.header_length, 4)
    local unknown1 		= buf(offset.header_unknown_type1, 2)
    local msg_count 	= buf(offset.header_msg_count, 2)
    local unknown2 		= buf(offset.header_unknown_type2, 1)
    local compressed	= buf(offset.header_is_compressed, 1)

    -- converted vals
    local timestamp_nst = timestamp_to_nstime(timestamp:le_uint64())

    -- fields
    tree:add(pfield.header_timestamp, timestamp, timestamp_nst)
    tree:add_le(pfield.header_len, header_len)
    tree:add_le(pfield.header_msg_count, msg_count)
    tree:add(pfield.header_is_compressed, compressed)

    -- add unknown fields
    local utree = tree:add(buf(0,0), "Unknown Fields")
    utree:add(pfield.header_unknown0, unknown0)
    utree:add_le(pfield.header_unknown_count, unknown1)
    utree:add_le(pfield.header_unknown2, unknown2)

    return header_len
end

function dissect_messages(buf, pinfo, tree)

end

-- takes uint64 value as unix time(ms), convert it to nstime
function timestamp_to_nstime(timestamp)
    local ts_sec = (timestamp / 1000):tonumber()
    local ts_nano = (timestamp % 1000):tonumber() * 1000000
    return NSTime.new(ts_sec, ts_nano)
end

init()
