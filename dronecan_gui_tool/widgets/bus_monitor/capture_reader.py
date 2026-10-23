#
# Copyright (C) 2016  UAVCAN Development Team  <uavcan.org>
#
# This software is distributed under the terms of the MIT License.
#

"""
Reads CAN frames from capture files in the Linux SocketCAN format (LINKTYPE_CAN_SOCKETCAN): pcapng files, such as
the logs written by the bus monitor or captured with Wireshark, and classic pcap files, such as those written by
tcpdump. Interfaces and records of other link types are skipped.
References:
    https://www.ietf.org/archive/id/draft-ietf-opsawg-pcapng-02.html
    https://www.tcpdump.org/linktypes/LINKTYPE_CAN_SOCKETCAN.html
"""

import struct
from dronecan.driver import CANFrame

LINKTYPE_CAN_SOCKETCAN = 227

_PCAPNG_SECTION_HEADER = 0x0A0D0D0A
_PCAPNG_INTERFACE_DESCRIPTION = 0x00000001
_PCAPNG_ENHANCED_PACKET = 0x00000006
_PCAPNG_BYTE_ORDER_MAGIC = 0x1A2B3C4D

_OPT_END_OF_OPTIONS = 0
_OPT_IF_TSRESOL = 9
_OPT_EPB_FLAGS = 2
_EPB_FLAGS_DIRECTION_MASK = 0b11
_EPB_FLAGS_OUTBOUND = 0b10

_PCAP_MAGIC_MICROSECONDS = 0xA1B2C3D4
_PCAP_MAGIC_NANOSECONDS = 0xA1B23C4D

_CAN_EFF_FLAG = 0x80000000
_CAN_RTR_FLAG = 0x40000000
_CAN_ERR_FLAG = 0x20000000
_CAN_EFF_MASK = 0x1FFFFFFF
_CAN_SFF_MASK = 0x000007FF
_CANFD_FDF = 0x04
_SOCKETCAN_HEADER_LENGTH = 8
_CANFD_FRAME_LENGTH = 72


class CaptureFormatError(Exception):
    pass


def _parse_socketcan_packet(packet, ts_real):
    """Returns a CANFrame, or None for error frames and truncated packets."""
    if len(packet) < _SOCKETCAN_HEADER_LENGTH:
        return None
    can_id, length, fd_flags = struct.unpack('>IBB', packet[:6])
    if can_id & _CAN_ERR_FLAG:
        return None
    extended = bool(can_id & _CAN_EFF_FLAG)
    # Older writers do not set the FD flag, but CAN FD frames are always stored in full
    canfd = bool(fd_flags & _CANFD_FDF) or len(packet) == _CANFD_FRAME_LENGTH
    data = packet[_SOCKETCAN_HEADER_LENGTH:_SOCKETCAN_HEADER_LENGTH + length]
    return CANFrame(can_id & (_CAN_EFF_MASK if extended else _CAN_SFF_MASK), bytes(data), extended,
                    ts_monotonic=ts_real, ts_real=ts_real, canfd=canfd)


def _iter_options(data, endian):
    offset = 0
    while offset + 4 <= len(data):
        code, length = struct.unpack(endian + 'HH', data[offset:offset + 4])
        if code == _OPT_END_OF_OPTIONS:
            return
        yield code, data[offset + 4:offset + 4 + length]
        offset += 4 + length + (-length % 4)


def _timestamp_resolution(tsresol):
    # The most significant bit selects a power of 2 instead of a power of 10
    if tsresol & 0x80:
        return 2.0 ** -(tsresol & 0x7F)
    return 10.0 ** -tsresol


def _read_pcapng(f):
    endian = '<'
    interfaces = []     # (link type, timestamp resolution) per interface of the current section
    while True:
        header = f.read(8)
        if len(header) < 8:
            return
        block_type = struct.unpack('<I', header[:4])[0]
        if block_type == _PCAPNG_SECTION_HEADER:
            magic = f.read(4)
            endian = '<' if struct.unpack('<I', magic)[0] == _PCAPNG_BYTE_ORDER_MAGIC else '>'
            if struct.unpack(endian + 'I', magic)[0] != _PCAPNG_BYTE_ORDER_MAGIC:
                raise CaptureFormatError('Invalid pcapng section header')
            total_length = struct.unpack(endian + 'I', header[4:])[0]
            f.read(total_length - 12)
            interfaces = []
            continue

        block_type, total_length = struct.unpack(endian + 'II', header)
        if total_length < 12 or total_length % 4:
            raise CaptureFormatError('Invalid pcapng block length %d' % total_length)
        body = f.read(total_length - 8)
        if len(body) < total_length - 8:
            return      # Truncated file, e.g. one that is still being written
        body = body[:-4]

        if block_type == _PCAPNG_INTERFACE_DESCRIPTION:
            link_type = struct.unpack(endian + 'H', body[:2])[0]
            resolution = 1e-6
            for code, value in _iter_options(body[8:], endian):
                if code == _OPT_IF_TSRESOL and value:
                    resolution = _timestamp_resolution(value[0])
            interfaces.append((link_type, resolution))

        elif block_type == _PCAPNG_ENHANCED_PACKET:
            interface_id, ts_high, ts_low, captured_length = struct.unpack(endian + 'IIII', body[:16])
            if interface_id >= len(interfaces) or interfaces[interface_id][0] != LINKTYPE_CAN_SOCKETCAN:
                continue
            packet = body[20:20 + captured_length]
            options = body[20 + captured_length + (-captured_length % 4):]
            direction = 'rx'
            for code, value in _iter_options(options, endian):
                if code == _OPT_EPB_FLAGS and len(value) >= 4:
                    if struct.unpack(endian + 'I', value[:4])[0] & _EPB_FLAGS_DIRECTION_MASK == _EPB_FLAGS_OUTBOUND:
                        direction = 'tx'
            ts_real = ((ts_high << 32) | ts_low) * interfaces[interface_id][1]
            frame = _parse_socketcan_packet(packet, ts_real)
            if frame is not None:
                yield direction, frame


def _read_pcap(f, header):
    magic = struct.unpack('<I', header[:4])[0]
    endian = '<' if magic in (_PCAP_MAGIC_MICROSECONDS, _PCAP_MAGIC_NANOSECONDS) else '>'
    magic = struct.unpack(endian + 'I', header[:4])[0]
    resolution = 1e-9 if magic == _PCAP_MAGIC_NANOSECONDS else 1e-6
    rest = f.read(20)
    if len(rest) < 20:
        raise CaptureFormatError('Truncated pcap header')
    link_type = struct.unpack(endian + 'I', rest[16:20])[0] & 0x0FFFFFFF
    if link_type != LINKTYPE_CAN_SOCKETCAN:
        raise CaptureFormatError('The capture is not in the SocketCAN format (link type %d)' % link_type)
    while True:
        record = f.read(16)
        if len(record) < 16:
            return
        seconds, fraction, captured_length, _ = struct.unpack(endian + 'IIII', record)
        packet = f.read(captured_length)
        if len(packet) < captured_length:
            return
        frame = _parse_socketcan_packet(packet, seconds + fraction * resolution)
        if frame is not None:
            yield 'rx', frame       # pcap does not record the direction


def read_can_capture(path):
    """
    Yields (direction, CANFrame) for every CAN frame in the file, where direction is 'rx' or 'tx'.
    Raises CaptureFormatError if the file is not a pcapng or pcap capture.
    """
    with open(path, 'rb') as f:
        header = f.read(4)
        if len(header) < 4:
            raise CaptureFormatError('The file is empty')
        if struct.unpack('<I', header)[0] == _PCAPNG_SECTION_HEADER:
            f.seek(0)
            yield from _read_pcapng(f)
        elif struct.unpack('<I', header)[0] in (_PCAP_MAGIC_MICROSECONDS, _PCAP_MAGIC_NANOSECONDS) or \
                struct.unpack('>I', header)[0] in (_PCAP_MAGIC_MICROSECONDS, _PCAP_MAGIC_NANOSECONDS):
            yield from _read_pcap(f, header)
        else:
            raise CaptureFormatError('The file is not a pcapng or pcap capture')
