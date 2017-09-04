-- internal constants
local FRAME_HEADER_LEN = 40
local MSG_HEADER_LEN = 16
local INVALID_ENTITY_ID = 0xE0000000 -- reffered as INVALID_GAME_OBJECT_ID in lua dump

-- create protocol
local ffxiv_proto = Proto("ffxiv", "FINAL FANTASY XIV Network Protocol")
-- generic header offset
local OFFSET_HEADER_TIMESTAMP         = 0x10 -- unixtime in millisecond
local OFFSET_HEADER_FRAME_LEN         = 0x18 -- frame length in bytes (includes 40bytes header!)
local OFFSET_HEADER_UNKNOWN1          = 0x1C
-- message header offset
local OFFSET_HEADER_MSG_COUNT         = 0x1E -- number of messages in packet frame
local OFFSET_HEADER_UNKNOWN2          = 0x20
local OFFSET_HEADER_MSG_COMPRESSED    = 0x21 -- if 1, payload is compressed with deflate

-- message subheader offset
local OFFSET_SUBHEADER_MSG_SRC  = 0x4
local OFFSET_SUBHEADER_MSG_DST  = 0x8
local OFFSET_SUBHEADER_MSG_TYPE = 0xC
local OFFSET_SUBHEADER_MSG_OPCODE = 0x12
local OFFSET_SUBHEADER_MSG_TIMESTAMP = 0x14
local OFFSET_SUBHEADER_MSG_DATA = 0x20

-- field display
local MESSAGE_TYPE_DISPLAY = {
    [1] = "ClientWorld",
    [2] = "ServerWorld",
    [3] = "Game", -- also used in FFXIV 1.0?
    [7] = "Ping",
    [8] = "Pong",
    [9] = "ClientHandshake",
    [10] = "ServerHandshake",
}

local MESSAGE_OPCODE_DISPLAY = {
    [0x142] = "ActorEvent",
}

-- Protocol fields
local proto_field = {
    -- generic header fields
    frame_unknown0  = ProtoField.bytes("ffxiv.frame.unknown0", "Unknown0"),
    frame_unknown1  = ProtoField.uint16("ffxiv.frame.unknown1", "Connection Type"),
    frame_unknown2  = ProtoField.bool("ffxiv.frame.unknown2", "Unknown2"),
    frame_len       = ProtoField.uint32("ffxiv.frame.length", "Frame Length"),
    frame_timestamp = ProtoField.absolute_time("ffxiv.frame.timestamp", "Frame Timestamp"),

    -- message fields
    msg_count      = ProtoField.uint16("ffxiv.message.count", "Message Count"),
    msg_compressed = ProtoField.bool("ffxiv.message.compressed", "Payload is Compressed?"),
    msg_len        = ProtoField.uint32("ffxiv.message.length", "Message Length"),
    msg_type       = ProtoField.uint16("ffxiv.message.type", "Message Type", nil, MESSAGE_TYPE_DISPLAY),
    msg_source_ent = ProtoField.uint32("ffxiv.message.source_ent", "Source Entity", base.HEX),
    msg_target_ent = ProtoField.uint32("ffxiv.message.target_ent", "Target Entity", base.HEX),
    msg_opcode     = ProtoField.uint16("ffxiv.message.opcode", "Opcode", base.HEX, MESSAGE_OPCODE_DISPLAY),
    -- msg_timestamp  = ProtoField.new("ffxiv.message.timestamp", "Message Timestamp", ftypes.ABSOLUTE_TIME),
    msg_data  = ProtoField.bytes("ffxiv.message.data", "Data"),
}
ffxiv_proto.fields = proto_field

function ffxiv_proto.init()
    -- do nothing
end

function ffxiv_proto.dissector(buf, pkt_info, tree)
    local buf_offset = 0

    while buf:len() > buf_offset do
        local frame_buf = buf:range(buf_offset)
        local result = dissect_frame(frame_buf, pkt_info, tree)
        if result > 0 then
            -- successfully dissected!
            pkt_info.cols.protocol = "FFXIV" -- set protocol name
            buf_offset = buf_offset + result
        elseif result < 0 then
            -- need more data!
            local bytes_needed = -result
            pkt_info.desegment_offset = buf_offset
            pkt_info.desegment_len = bytes_needed

            -- set to eof
            buf_offset = buf:len()
        else
            -- result == 0 means error while dissecting it
            break
        end
    end

    return buf_offset
end

-- TODO: split function
function dissect_frame(buf, pkt_info, tree)
    local frame_len = check_frame_length(buf)
    if frame_len <= 0 then return frame_len end -- error or need more bytes

    -- we're good now, let's dissect it!
    local buf = buf:range(0, frame_len) -- ignore after frame length
    local ffxiv_tree = tree:add(ffxiv_proto, buf)

    -- TODO: maybe just split between parsing part and tree part?
    -- because it's bit stupid to place here for field order
    ffxiv_tree:add(proto_field.frame_unknown0, buf(0, 16))
    ffxiv_tree:add_le(proto_field.frame_unknown1, buf(OFFSET_HEADER_UNKNOWN1, 2))
    ffxiv_tree:add_le(proto_field.frame_unknown2, buf(OFFSET_HEADER_UNKNOWN2, 1))

    -- add frame length
    ffxiv_tree:add_le(proto_field.frame_len, get_frame_length_tvb(buf))

    -- add frame timestamp
    local frame_timestamp     = buf(OFFSET_HEADER_TIMESTAMP, 8)
    local frame_timestamp_nst = unix_milliseconds_to_nst(frame_timestamp:le_uint64())
    ffxiv_tree:add(proto_field.frame_timestamp, frame_timestamp, frame_timestamp_nst)

    -- add compress info
    local msg_compressed = buf(OFFSET_HEADER_MSG_COMPRESSED, 1)
    ffxiv_tree:add_le(proto_field.msg_compressed, msg_compressed)

    -- add message tree
    local msg_buf = buf:range(FRAME_HEADER_LEN) -- skip header length
    local msg_tree = ffxiv_tree:add(msg_buf, "Messages")

    -- add message count
    -- do note that this info still comes from the frame header
    local msg_count = buf(OFFSET_HEADER_MSG_COUNT, 2)
    msg_tree:add_le(proto_field.msg_count, msg_count)

    -- inflate first if compressed
    if msg_compressed:uint() == 1 then
        msg_buf = msg_buf:uncompress()
    end
    dissect_payload(msg_buf, pkt_info, msg_tree) -- dissect payload

    return frame_len
end

function dissect_payload(buf, pkt_info, tree)
    -- do nothing
    local offset = 0
    while buf:len() > offset do
        local msg_len_tvb = buf:range(offset, 4)
        local msg_len = msg_len_tvb:le_uint()
        if msg_len == 0 then
            -- invalid length
            -- TODO: error expert
            return
        end

        local msg_buf = buf:range(offset, msg_len)

        -- create tree
        local msg_tree = tree:add(msg_buf, string.format("Message (%i bytes)", msg_len))

        -- add msg len
        msg_tree:add_le(proto_field.msg_len, msg_len_tvb)

        -- dissect messages
        dissect_message_payload(msg_buf, pkt_info, msg_tree)

        offset = offset + msg_len
    end
end

function dissect_message_payload(buf, pkt_info, tree)
    tree:add_le(proto_field.msg_source_ent, buf(OFFSET_SUBHEADER_MSG_SRC, 4))
    tree:add_le(proto_field.msg_target_ent, buf(OFFSET_SUBHEADER_MSG_DST, 4))

    local msg_type_tvb = buf(OFFSET_SUBHEADER_MSG_TYPE, 2)
    tree:add_le(proto_field.msg_type, msg_type_tvb)
    if msg_type_tvb:le_uint() == 3 then
        -- message
        tree:add_le(proto_field.msg_opcode, buf(OFFSET_SUBHEADER_MSG_OPCODE, 2))
        -- tree:add_le(proto_field.msg_timestamp, buf(OFFSET_SUBHEADER_MSG_TIMESTAMP, 4))
        local data_len = buf:len() - 0x20
        if data_len > 0 then
            tree:add(proto_field.msg_data, buf(OFFSET_SUBHEADER_MSG_DATA, data_len))
        end
    end
end

function check_frame_length(buf)
    if buf:len() < OFFSET_HEADER_FRAME_LEN + 4 then
        -- too short to get a frame length!
        return -DESEGMENT_ONE_MORE_SEGMENT
    end

    local frame_len = get_frame_length_tvb(buf):le_uint()
    if buf:len() < frame_len then -- if buffer is smaller than frame length
        -- then we need more bytes!
        return -(frame_len - buf:len())
    end

    return frame_len
end

-- get frame length from the header buffer
function get_frame_length_tvb(buf)
    return buf:range(OFFSET_HEADER_FRAME_LEN, 4)
end

-- attempt to find a packet that follows FFXIV packet convention
ffxiv_proto:register_heuristic("tcp", function (buf, pkt_info, tree)
    -- check if packet has enough room for header
    if buf:len() < FRAME_HEADER_LEN then
        return false
    end

    -- check if first 16 bytes are equal to predefined value
    local sig_expected = ByteArray.new("52 52 A0 41 FF 5D 46 E2 7F 2A 64 4D 7B 99 C4 75")
    if buf(0, 16):tvb() ~= sig_expected:tvb() then
        -- return false if does not match
        return false
    end

    -- looks like a packet from FFXIV! so let's dissect it!
    ffxiv_proto.dissector(buf, pkt_info, tree)
    -- use ffxiv dissector for same addr:port
    pkt_info.conversation = ffxiv_proto

    return true
end)

-- takes uint64 timestamp as a unix epoch in millisecond,
-- convert it to NSTime
function unix_milliseconds_to_nst(timestamp)
    local ts_sec = (timestamp / 1000):tonumber()
    local ts_nano = (timestamp % 1000):tonumber() * 1000000
    return NSTime.new(ts_sec, ts_nano)
end

-- register it for tcp port 42424 (used by algo project)
local tcp_table = DissectorTable.get("tcp.port")
tcp_table:add(42424, ffxiv_proto)
