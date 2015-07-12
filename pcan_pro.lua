
--  Usage: wireshark -X lua_script:pcan_pro.lua

p_pcan_pro = Proto("pcan_pro", "Peak CAN USB Pro")

-- USB Command Record Types
local record_types = {
    [0x02] = "Set Bitrate",
    [0x04] = "Set Bus Active",
    [0x05] = "Set Silent",
    [0x07] = "CMD 0x07",
    [0x0a] = "Set Filter",
    [0x0C] = "CMD 0x0C",
    [0x10] = "Set Timestamp",
    [0x11] = "CMD 0x11 (switch busload on/off)",
    [0x12] = "Get Device ID",
    [0x1C] = "Set LED",
    [0x80] = "RX Message (8 bytes)",
    [0x81] = "RX Message (4 bytes)",
    [0x82] = "RX Message (0 bytes)",
    [0x83] = "RX RTR Message",
    [0x84] = "RX Status",
    [0x85] = "RX Timestamp",
    [0x86] = "Busload Info",
    [0x41] = "TX Message (8 bytes)",
    [0x42] = "TX Message (4 bytes)",
    [0x43] = "TX Message (0 bytes)"
}

local record_lengths = {
    [0x02] = 8,
    [0x04] = 4,
    [0x05] = 4,
    [0x07] = 4,
    [0x0A] = 4,
    [0x0C] = 8,
    [0x10] = 4,
    [0x11] = 8,
    [0x12] = 8,
    [0x1C] = 8,
    [0x80] = 20,
    [0x81] = 16,
    [0x82] = 12,
    [0x83] = 12,
    [0x84] = 12,
    [0x85] = 12,
    [0x86] = 8,
    [0x41] = 16,
    [0x42] = 12,
    [0x43] = 8
}

-- Create the fields exhibited by the protocol.
p_pcan_pro.fields.rec_cnt_rd  = ProtoField.uint16("pcan_pro.rec_cnt_rd", "Record Count", base.DEC)
p_pcan_pro.fields.msg_cnt     = ProtoField.uint16("pcan_pro.msg_cnt", "Device Message Counter", base.DEC)
p_pcan_pro.fields.command     = ProtoField.uint16("pcan_pro.cmd", "Command ID", base.DEC, record_types)
p_pcan_pro.fields.channel     = ProtoField.uint8("pcan_pro.channel", "Channel", base.DEC)
p_pcan_pro.fields.client      = ProtoField.uint8("pcan_pro.client", "Client", base.DEC)
p_pcan_pro.fields.flags       = ProtoField.uint8("pcan_pro.flags", "Flags", base.HEX)
p_pcan_pro.fields.dlc         = ProtoField.uint8("pcan_pro.dlc", "DLC", base.DEC)

p_pcan_pro.fields.id          = ProtoField.uint32("pcan_pro.id", "ID", base.HEX)
p_pcan_pro.fields.ext_id      = ProtoField.bool("pcan_pro.ext_id", "Extended ID")
p_pcan_pro.fields.rtr         = ProtoField.bool("pcan_pro.rtr", "Request Transmit")

p_pcan_pro.fields.data        = ProtoField.bytes("pcan_pro.data", "Data")

p_pcan_pro.fields.ccbt        = ProtoField.uint32("pcan_pro.ccbt", "CCBT", base.HEX)
p_pcan_pro.fields.sample3     = ProtoField.bool("pcan_pro.sample3", "3 samples mode")
p_pcan_pro.fields.sjw         = ProtoField.uint8("pcan_pro.sjw", "SJW", base.HEX_DEC)
p_pcan_pro.fields.phase_seg2  = ProtoField.uint8("pcan_pro.phase_seg2", "Phase Segment 2", base.HEX_DEC)
p_pcan_pro.fields.t_seg       = ProtoField.uint8("pcan_pro.t_seg", "T Segment 1", base.HEX_DEC)
p_pcan_pro.fields.brp         = ProtoField.uint16("pcan_pro.brp", "BRP", base.HEX_DEC)

p_pcan_pro.fields.silent      = ProtoField.uint16("pcan_pro.silent", "Silent Mode", base.HEX)
p_pcan_pro.fields.filter_mode = ProtoField.uint16("pcan_pro.filter_mode", "Filter Mode", base.HEX)
p_pcan_pro.fields.ts_mode     = ProtoField.uint16("pcan_pro.ts_mode", "Timestamp Mode", base.HEX)
p_pcan_pro.fields.bus_active  = ProtoField.uint16("pcan_pro.bus_active", "Bus Active Mode", base.HEX)
p_pcan_pro.fields.ts_data     = ProtoField.bytes("pcan_pro.ts_data", "Timestamp Data")
p_pcan_pro.fields.rx_status   = ProtoField.uint16("pcan_pro.rx_status", "RX Status", base.HEX)
p_pcan_pro.fields.rx_err_cnt  = ProtoField.uint8("pcan_pro.rx_err_cnt", "RX Error Counter", base.DEC)
p_pcan_pro.fields.tx_err_cnt  = ProtoField.uint8("pcan_pro.tx_err_cnt", "TX Error Counter", base.DEC)
p_pcan_pro.fields.timestamp   = ProtoField.uint32("pcan_pro.timestamp", "Timestamp (us)", base.DEC)
p_pcan_pro.fields.error_frame = ProtoField.uint32("pcan_pro.error_frame", "Error Frame", base.HEX)

p_pcan_pro.fields.led_mode    = ProtoField.uint16("pcan_pro.led_mode", "LED Mode", base.HEX)
p_pcan_pro.fields.led_timeout = ProtoField.uint32("pcan_pro.led_timeout", "LED Timeout", base.DEC)
p_pcan_pro.fields.serial_num  = ProtoField.uint32("pcan_pro.serial_num", "Serial Number", base.DEC)

p_pcan_pro.fields.busload     = ProtoField.uint16("pcan_pro.busload", "Busload", base.DEC)
p_pcan_pro.fields.unknown     = ProtoField.bytes("pcan_pro.unknown", "Unidentified message data")

-- Referenced USB URB dissector fields.
local f_urb_type = Field.new("usb.urb_type")
local f_transfer_type = Field.new("usb.transfer_type")
local f_endpoint = Field.new("usb.endpoint_number.endpoint")
local f_len = Field.new("frame.len")

local function warn_undecoded(subtree, range)
    local item = subtree:add(p_pcan_pro.fields.unknown, range)
    item:add_expert_info(PI_UNDECODED, PI_WARN, "Leftover data")
end

local function dissect_flags(tvb, subtree)
    local flags = tvb(0,1):uint()
    subtree:add(p_pcan_pro.fields.ext_id, tvb(0,1), bit.band(flags, 0x02)~=0)
    subtree:add(p_pcan_pro.fields.rtr,    tvb(0,1), bit.band(flags, 0x01)~=0)
end

local function dissect_tx_message(tvb, pinfo, subtree)
    local dlc = tvb(3,1):uint()

    local channel = bit.rshift(dlc,4)
    dlc = bit.band(dlc, 0x0F)

    subtree:add(p_pcan_pro.fields.client, tvb(1,1))
    subtree:add(p_pcan_pro.fields.channel, tvb(3,1), channel)
    subtree:add(p_pcan_pro.fields.dlc, tvb(3,1), dlc)
    subtree:add(p_pcan_pro.fields.id, tvb(4,4), tvb(4,4):le_uint())

    dissect_flags(tvb(2,1), subtree)

    if (dlc>0) then
        subtree:add(p_pcan_pro.fields.data, tvb(8,dlc))
    end
end

local function dissect_rx_message(tvb, pinfo, subtree)
    local dlc = tvb(3,1):uint()
    local channel = bit.rshift(dlc,4)
    dlc = bit.band(dlc, 0x0F)
    subtree:add(p_pcan_pro.fields.client, tvb(1,1))
    subtree:add(p_pcan_pro.fields.channel, tvb(3,1), channel)
    subtree:add(p_pcan_pro.fields.dlc, tvb(3,1), dlc)
    subtree:add(p_pcan_pro.fields.id, tvb(8,4), tvb(8,4):le_uint())
    dissect_flags(tvb(2,1), subtree)

    subtree:add(p_pcan_pro.fields.timestamp, tvb(4,4), tvb(4,4):le_uint())

    if (dlc>0) then
        subtree:add(p_pcan_pro.fields.data, tvb(12,dlc))
    end
end

local function dissect_set_bitrate(tvb, pinfo, subtree)
    subtree:add(p_pcan_pro.fields.channel, tvb(1,1))
    
    local ccbt = tvb(4,4):le_uint()
    local sample3_mode = (bit.band(ccbt, 0x00800000) == 0x00800000);
    local sjw = bit.rshift(ccbt, 24) + 1
    local phase_seg2 = bit.band(bit.rshift(ccbt, 20), 0x0F) + 1
    local t_seg = bit.band(bit.rshift(ccbt, 16), 0x0F) + 1
    local brp = bit.band(ccbt, 0xFFFF) + 1

    subtree:add(p_pcan_pro.fields.ccbt, tvb(4,4), ccbt)
    subtree:add(p_pcan_pro.fields.sample3, sample3_mode)
    subtree:add(p_pcan_pro.fields.sjw, sjw)
    subtree:add(p_pcan_pro.fields.phase_seg2, phase_seg2)
    subtree:add(p_pcan_pro.fields.t_seg, t_seg)
    subtree:add(p_pcan_pro.fields.brp, brp)
end

local function dissect_set_silent(tvb, pinfo, subtree)
    subtree:add(p_pcan_pro.fields.channel, tvb(1,1))
    subtree:add(p_pcan_pro.fields.silent, tvb(2,2), tvb(2,2):le_uint())
end

local function dissect_set_led(tvb, pinfo, subtree)
    subtree:add(p_pcan_pro.fields.channel, tvb(1,1))
    subtree:add(p_pcan_pro.fields.led_mode, tvb(2,2), tvb(2,2):le_uint())
    subtree:add(p_pcan_pro.fields.led_timeout, tvb(4,4), tvb(4,4):le_uint())
end

local function dissect_dev_id(tvb, pinfo, subtree)
    subtree:add(p_pcan_pro.fields.channel, tvb(1,1))
    subtree:add(p_pcan_pro.fields.serial_num, tvb(4,4), tvb(4,4):le_uint())
end

local function dissect_set_filter(tvb, pinfo, subtree)
    subtree:add(p_pcan_pro.fields.filter_mode, tvb(2,2), tvb(2,2):le_uint())
end

local function dissect_set_ts_mode(tvb, pinfo, subtree)
    subtree:add(p_pcan_pro.fields.ts_mode, tvb(2,2), tvb(2,2):le_uint())
end

local function dissect_set_bus_active(tvb, pinfo, subtree)
    subtree:add(p_pcan_pro.fields.channel, tvb(1,1))
    subtree:add(p_pcan_pro.fields.bus_active, tvb(2,2), tvb(2,2):le_uint())
end

local function dissect_rx_status(tvb, pinfo, subtree)
    local raw_status = tvb(2,2):le_uint()
    local channel = tvb(1,1):le_uint()
    channel = bit.band(bit.rshift(channel, 4), 0x0F)

    local err_frm = tvb(8,4):le_uint()
    local rx_err_cnt = bit.rshift(bit.band(err_frm, 0x00ff0000), 16)
    local tx_err_cnt = bit.rshift(bit.band(err_frm, 0xff000000), 24)

    subtree:add(p_pcan_pro.fields.channel, channel)
    subtree:add(p_pcan_pro.fields.rx_status, tvb(2,2), raw_status)
    subtree:add(p_pcan_pro.fields.timestamp, tvb(4,4), tvb(4,4):le_uint())
    subtree:add(p_pcan_pro.fields.error_frame, tvb(8,4), tvb(8,4):le_uint())
    subtree:add(p_pcan_pro.fields.rx_err_cnt, tvb(10,1), rx_err_cnt)
    subtree:add(p_pcan_pro.fields.tx_err_cnt, tvb(11,1), tx_err_cnt)
end

local function dissect_rx_timestamp(tvb, pinfo, subtree)
    subtree:add(p_pcan_pro.fields.ts_data, tvb(4,8))
    subtree:add(p_pcan_pro.fields.timestamp, tvb(8,4), tvb(8,4):le_uint())
end

local function dissect_busload(data, pinfo, subtree)
    channel = bit.band(bit.rshift(data(1,1):uint(), 4), 0x0F)
    subtree:add(p_pcan_pro.fields.unknown, data(1,3))
    subtree:add(p_pcan_pro.fields.channel, data(1,1), channel)
    subtree:add(p_pcan_pro.fields.busload, data(2,2), data(2,2):le_uint())
    subtree:add(p_pcan_pro.fields.timestamp, data(4,4), data(4,4):le_uint())
end

local function dissect_0x11(data, pinfo, subtree)
    subtree:add(p_pcan_pro.fields.channel, data(1,1):uint())
    subtree:add(p_pcan_pro.fields.unknown, data(2,6))
    -- data(2,1) always ==0x61 ?
    -- data(3,1) == on/off?
end


function p_pcan_pro.dissector(tvb, pinfo, tree)
    local transfer_type = tonumber(tostring(f_transfer_type()))

    -- Bulk transfers only.
    if transfer_type == 3 then
        local urb_type = tonumber(tostring(f_urb_type()))
        local endpoint = tonumber(tostring(f_endpoint()))
        local f_len = tonumber(tostring(f_len()))-64

        -- Payload-carrying packets only.
        if ( 
             ( (urb_type == 0x53) and ( (endpoint == 1) or (endpoint == 2) or (endpoint == 3) ) )
             or ( (urb_type == 0x43) and ( (endpoint == 1) or (endpoint == 0x02) ) ) 
           )
        then
            local rec_cnt_rd = tvb(0,2):le_uint()
            tree:add(p_pcan_pro.fields.rec_cnt_rd, tvb(0,2), rec_cnt_rd);
            tree:add(p_pcan_pro.fields.msg_cnt, tvb(2,2), tvb(2,2):le_uint())

            local pos = 4
            local info = "PCAN: "
            local records = 0
            while (records<rec_cnt_rd) do

                local command = tvb(pos,1):uint()
                if (command==0) then 
                    return pos 
                end

                pinfo.cols.protocol = p_pcan_pro.name
                if (record_types[command]) then
                    if (pos>4) then info = info .. ", " end
                    info = info .. record_types[command]
                    pinfo.cols.info = info
                else
                    warn_undecoded(tree, tvb(pos))
                    pinfo.cols.info = info .. string.format("UNKNOWN CMD: 0x%02X", command)
                    return 0
                end

                local record_len = record_lengths[command]
                local data = tvb(pos, record_len)

                local subtree = tree:add(p_pcan_pro, data(), "pcan record: " .. record_types[command])
                subtree:add(p_pcan_pro.fields.command, command):set_generated()

                if (command==0x41) or (command==0x42) or (command==0x43) then
                    dissect_tx_message(data, pinfo, subtree)
                elseif (command==0x80) or (command==0x81) or (command==0x82) or (command==0x83) then
                    dissect_rx_message(data, pinfo, subtree)
                elseif (command==0x02) then
                    dissect_set_bitrate(data, pinfo, subtree)
                elseif (command==0x04) then
                    dissect_set_bus_active(data, pinfo, subtree)
                elseif (command==0x05) then
                    dissect_set_silent(data, pinfo, subtree)
                elseif (command==0x0A) then
                    dissect_set_filter(data, pinfo, subtree)
                elseif (command==0x10) then
                    dissect_set_ts_mode(data, pinfo, subtree)
                elseif (command==0x11) then
                    dissect_0x11(data, pinfo, subtree)
                elseif (command==0x12) then
                    dissect_dev_id(data, pinfo, subtree)
                elseif (command==0x1C) then
                    dissect_set_led(data, pinfo, subtree)
                elseif (command==0x84) then
                    dissect_rx_status(data, pinfo, subtree)
                elseif (command==0x85) then
                    dissect_rx_timestamp(data, pinfo, subtree)
                elseif (command==0x86) then
                    dissect_busload(data, pinfo, subtree)
                end

                pos = pos + record_len
                records = records + 1

            end

            return 0
        end

    end
    return 0
end

function p_pcan_pro.init()
    local usb_bulk_dissectors = DissectorTable.get("usb.bulk")
    usb_bulk_dissectors:add(0xFF, p_pcan_pro)
    usb_bulk_dissectors:add(0xFFFF, p_pcan_pro)
    usb_bulk_dissectors:add(0x00, p_pcan_pro)
end

