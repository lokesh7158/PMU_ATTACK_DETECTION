import datetime
import math
import struct


# ---------------- CRC ----------------
def crc_ccitt(data: bytes):
    crc = 0xFFFF
    for b in data:
        crc ^= b << 8
        for _ in range(8):
            if crc & 0x8000:
                crc = (crc << 1) ^ 0x1021
            else:
                crc <<= 1
            crc &= 0xFFFF
    return crc


# ---------------- FRAME TYPE ----------------
def get_frame_type(sync):
    second_byte = sync & 0x00FF
    return (second_byte & 0xF0) >> 4


# ---------------- STAT DECODER ----------------
def decode_stat(stat):
    return {
        "data_error": bool(stat & 0x8000),
        "pmu_error": bool(stat & 0x4000),
        "time_sync": not bool(stat & 0x2000),
        "data_sorting": (stat >> 11) & 0x03,
    }


def read_name(payload, offset):
    if offset >= len(payload):
        return "", 0

    length = payload[offset]
    if length == 0 or offset + 1 + length > len(payload):
        return "", 1

    name = payload[offset + 1: offset + 1 + length].decode("utf-8", errors="ignore")
    return name, 1 + length


def read_float(payload, offset):
    return struct.unpack(">f", payload[offset:offset+4])[0]


def parse_header(frame):
    if len(frame) < 6:
        raise ValueError("frame too short for header")
    sync = struct.unpack(">H", frame[0:2])[0]
    framesize = struct.unpack(">H", frame[2:4])[0]
    stream_id = struct.unpack(">H", frame[4:6])[0]
    return sync, framesize, stream_id


# ---------------- CONFIG DECODER ----------------
def decode_complete_config(payload):
    try:
        if len(payload) < 6:
            return {"error": "config payload too short"}

        time_base_raw = struct.unpack(">I", payload[0:4])[0]
        time_base = time_base_raw & 0x00FFFFFF
        offset = 4

        has_pdc_name = False
        pdc_name = ""
        if offset < len(payload):
            pdc_len_peek = payload[offset]
            num_with_pdc = 65535
            num_no_pdc = 65535

            if offset + 1 + pdc_len_peek + 2 <= len(payload):
                num_with_pdc = struct.unpack(">H", payload[offset + 1 + pdc_len_peek: offset + 1 + pdc_len_peek + 2])[0]

            if offset + 2 <= len(payload):
                num_no_pdc = struct.unpack(">H", payload[offset:offset+2])[0]

            with_ok = 1 <= num_with_pdc <= 64
            none_ok = 1 <= num_no_pdc <= 64
            if with_ok and not none_ok:
                has_pdc_name = True
            elif none_ok and not with_ok:
                has_pdc_name = False
            else:
                has_pdc_name = True

        if has_pdc_name:
            pdc_len = payload[offset]
            offset += 1
            if pdc_len > 0 and offset + pdc_len <= len(payload):
                pdc_name = payload[offset:offset + pdc_len].decode("utf-8", errors="ignore")
            offset += pdc_len

        if offset + 2 > len(payload):
            return {"error": "missing NUM_PMU"}

        num_pmu = struct.unpack(">H", payload[offset:offset+2])[0]
        offset += 2

        pmus = []
        for pmu_index in range(1, num_pmu + 1):
            pmu_name, consumed = read_name(payload, offset)
            offset += consumed

            if offset + 4 > len(payload):
                return {"error": "incomplete PMU header"}

            pmu_id = struct.unpack(">H", payload[offset:offset+2])[0]
            pmu_version = struct.unpack(">H", payload[offset+2:offset+4])[0]
            offset += 4

            if offset + 16 > len(payload):
                return {"error": "missing G_PMU_ID"}
            g_pmu_id = payload[offset:offset+16].hex()
            offset += 16

            format_word = struct.unpack(">H", payload[offset:offset+2])[0]
            offset += 2

            phnmr = struct.unpack(">H", payload[offset:offset+2])[0]
            annmr = struct.unpack(">H", payload[offset+2:offset+4])[0]
            frnmr = struct.unpack(">H", payload[offset+4:offset+6])[0]
            dfdtnmr = struct.unpack(">H", payload[offset+6:offset+8])[0]
            dgnmr = struct.unpack(">H", payload[offset+8:offset+10])[0]
            offset += 10

            ph_names = []
            for _ in range(phnmr):
                name, consumed = read_name(payload, offset)
                ph_names.append(name)
                offset += consumed

            fr_names = []
            for _ in range(frnmr):
                name, consumed = read_name(payload, offset)
                fr_names.append(name)
                offset += consumed

            rocof_names = []
            for _ in range(dfdtnmr):
                name, consumed = read_name(payload, offset)
                rocof_names.append(name)
                offset += consumed

            an_names = []
            for _ in range(annmr):
                name, consumed = read_name(payload, offset)
                an_names.append(name)
                offset += consumed

            dig_words = []
            for _ in range(dgnmr):
                bit_names = []
                for _ in range(16):
                    name, consumed = read_name(payload, offset)
                    bit_names.append(name)
                    offset += consumed
                dig_words.append(bit_names)

            phscales = []
            for _ in range(phnmr):
                if offset + 16 > len(payload):
                    return {"error": "incomplete PHSCALE"}
                phscales.append({
                    "mod_flags": struct.unpack(">I", payload[offset:offset+4])[0],
                    "scale": read_float(payload, offset + 4),
                    "angle_off": read_float(payload, offset + 8),
                    "vclass": read_float(payload, offset + 12),
                })
                offset += 16

            frscales = []
            for _ in range(frnmr):
                if offset + 8 > len(payload):
                    return {"error": "incomplete FRSCALE"}
                frscales.append({
                    "scale": read_float(payload, offset),
                    "offset": read_float(payload, offset + 4),
                })
                offset += 8

            dfdtscales = []
            for _ in range(dfdtnmr):
                if offset + 8 > len(payload):
                    return {"error": "incomplete DFDTSCALE"}
                dfdtscales.append({
                    "scale": read_float(payload, offset),
                    "offset": read_float(payload, offset + 4),
                })
                offset += 8

            anscales = []
            for _ in range(annmr):
                if offset + 8 > len(payload):
                    return {"error": "incomplete ANSCALE"}
                anscales.append({
                    "scale": read_float(payload, offset),
                    "offset": read_float(payload, offset + 4),
                })
                offset += 8

            dig_units = []
            for _ in range(dgnmr):
                if offset + 4 > len(payload):
                    return {"error": "incomplete DIGUNIT"}
                dig_units.append({
                    "normal": struct.unpack(">H", payload[offset:offset+2])[0],
                    "valid": struct.unpack(">H", payload[offset+2:offset+4])[0],
                })
                offset += 4

            if offset + 12 > len(payload):
                return {"error": "missing geographic metadata"}
            pmu_lat = read_float(payload, offset)
            pmu_lon = read_float(payload, offset + 4)
            pmu_elev = read_float(payload, offset + 8)
            offset += 12

            if offset + 2 > len(payload):
                return {"error": "missing PMUFLAG"}
            pmu_flag = struct.unpack(">H", payload[offset:offset+2])[0]
            offset += 2

            if offset + 8 > len(payload):
                return {"error": "missing timing metadata"}
            window = struct.unpack(">I", payload[offset:offset+4])[0]
            grp_dly = struct.unpack(">I", payload[offset+4:offset+8])[0]
            offset += 8

            if offset + 4 > len(payload):
                return {"error": "missing PMU_DATA_RATE/CFGCNT"}
            pmu_data_rate = struct.unpack(">h", payload[offset:offset+2])[0]
            pmu_cfgcnt = struct.unpack(">H", payload[offset+2:offset+4])[0]
            offset += 4

            pmus.append({
                "index": pmu_index,
                "name": pmu_name,
                "pmu_id": pmu_id,
                "pmu_version": pmu_version,
                "g_pmu_id": g_pmu_id,
                "format_word": format_word,
                "phasor_format": "float" if (format_word & 0x02) else "int",
                "phasor_encoding": "polar" if (format_word & 0x01) else "rect",
                "phnmr": phnmr,
                "annmr": annmr,
                "frnmr": frnmr,
                "dfdtnmr": dfdtnmr,
                "dgnmr": dgnmr,
                "ph_names": ph_names,
                "fr_names": fr_names,
                "rocof_names": rocof_names,
                "an_names": an_names,
                "dig_words": dig_words,
                "phscales": phscales,
                "frscales": frscales,
                "dfdtscales": dfdtscales,
                "anscales": anscales,
                "dig_units": dig_units,
                "pmu_lat": pmu_lat,
                "pmu_lon": pmu_lon,
                "pmu_elev": pmu_elev,
                "pmu_flag": pmu_flag,
                "window": window,
                "grp_dly": grp_dly,
                "pmu_data_rate": pmu_data_rate,
                "pmu_cfgcnt": pmu_cfgcnt,
            })

        stream_rate = None
        wait_time = None
        if offset + 4 <= len(payload):
            stream_rate = struct.unpack(">h", payload[offset:offset+2])[0]
            wait_time = struct.unpack(">H", payload[offset+2:offset+4])[0]
            offset += 4

        config = {
            "time_base": time_base,
            "pdc_name": pdc_name,
            "num_pmu": num_pmu,
            "stream_rate": stream_rate,
            "wait_time": wait_time,
            "pmus": pmus,
        }

        return {"config": config}

    except Exception as exc:
        return {"error": str(exc)}


def decode_config_frame(frame):
    if len(frame) < 16:
        return {"error": "frame too short"}

    cont_idx = struct.unpack(">H", frame[14:16])[0]
    payload = frame[16:-2]

    if cont_idx > 0:
        return {"fragment_payload": payload, "cont_idx": cont_idx}

    return decode_complete_config(payload)


def decode_data(frame, config):
    try:
        if len(frame) < 16:
            return {"error": "frame too short"}

        _, _, stream_id = parse_header(frame)
        soc = struct.unpack(">I", frame[6:10])[0]
        leap = frame[10]
        fracsec = int.from_bytes(frame[11:14], "big")
        recv_crc = struct.unpack(">H", frame[-2:])[0]
        calc_crc = crc_ccitt(frame[:-2])

        time_base = config.get("time_base") or 1000000
        timestamp = datetime.datetime.utcfromtimestamp(soc) + datetime.timedelta(seconds=fracsec / time_base)

        offset = 14
        pmus = []

        for pmu_cfg in config["pmus"]:
            if offset + 2 > len(frame) - 2:
                return {"error": "incomplete DATA PMU block"}

            stat = struct.unpack(">H", frame[offset:offset+2])[0]
            offset += 2
            tq_byte = frame[offset]
            tq_ns = frame[offset + 1] + (tq_byte & 0x0F) * 256
            tq_mult = (tq_byte & 0x70) >> 4
            tq_ver = bool(tq_byte & 0x80)
            offset += 2

            phasors = []
            fmt = pmu_cfg["phasor_format"]
            enc = pmu_cfg["phasor_encoding"]
            has_da = bool(pmu_cfg["pmu_flag"] & 0x1000)

            pmu_stat = decode_stat(stat)
            pmu_tq = {
                "ver": tq_ver,
                "mult": tq_mult,
                "ns": tq_ns,
            }

            for i in range(pmu_cfg["phnmr"]):
                ph_name = pmu_cfg["ph_names"][i] if i < len(pmu_cfg["ph_names"]) else f"Phasor[{i+1}]"
                if fmt == "float":
                    rx = read_float(frame, offset)
                    ry = read_float(frame, offset + 4)
                    if enc == "polar":
                        mag = rx
                        ang = ry
                        real = mag * math.cos(ang)
                        imag = mag * math.sin(ang)
                    else:
                        real = rx
                        imag = ry
                        mag = math.sqrt(real * real + imag * imag)
                        ang = math.atan2(imag, real)
                    phasors.append({"name": ph_name, "mag": mag, "ang": ang, "real": real, "imag": imag})
                    offset += 8
                else:
                    if enc == "polar":
                        mag = struct.unpack(">H", frame[offset:offset+2])[0]
                        ang_raw = struct.unpack(">h", frame[offset+2:offset+4])[0]
                        ang = ang_raw * 1e-4
                        real = mag * math.cos(ang)
                        imag = mag * math.sin(ang)
                        phasors.append({"name": ph_name, "mag": mag, "ang": ang, "real": real, "imag": imag})
                    else:
                        real = struct.unpack(">h", frame[offset:offset+2])[0]
                        imag = struct.unpack(">h", frame[offset+2:offset+4])[0]
                        mag = math.sqrt(real * real + imag * imag)
                        ang = math.atan2(imag, real)
                        phasors.append({"name": ph_name, "mag": mag, "ang": ang, "real": real, "imag": imag})
                    offset += 4

                if has_da:
                    offset += 2

            freqs = []
            if pmu_cfg["frnmr"] > 0:
                for i in range(pmu_cfg["frnmr"]):
                    fr_name = pmu_cfg["fr_names"][i] if i < len(pmu_cfg["fr_names"]) else f"Freq[{i+1}]"
                    if pmu_cfg["format_word"] & 0x08:
                        value = read_float(frame, offset)
                        offset += 4
                    else:
                        value = struct.unpack(">h", frame[offset:offset+2])[0]
                        offset += 2
                    freqs.append({"name": fr_name, "value": value})
                    if has_da:
                        offset += 2

            dfreqs = []
            if pmu_cfg["dfdtnmr"] > 0:
                for i in range(pmu_cfg["dfdtnmr"]):
                    rn = pmu_cfg["rocof_names"][i] if i < len(pmu_cfg["rocof_names"]) else f"ROCOF[{i+1}]"
                    if pmu_cfg["format_word"] & 0x08:
                        value = read_float(frame, offset)
                        offset += 4
                    else:
                        value = struct.unpack(">h", frame[offset:offset+2])[0]
                        offset += 2
                    dfreqs.append({"name": rn, "value": value})
                    if has_da:
                        offset += 2

            analogs = []
            for i in range(pmu_cfg["annmr"]):
                an_name = pmu_cfg["an_names"][i] if i < len(pmu_cfg["an_names"]) else f"Analog[{i+1}]"
                if pmu_cfg["format_word"] & 0x04:
                    value = read_float(frame, offset)
                    offset += 4
                else:
                    value = struct.unpack(">h", frame[offset:offset+2])[0]
                    offset += 2
                analogs.append({"name": an_name, "value": value})

            digitals = []
            for word_idx in range(pmu_cfg["dgnmr"]):
                value = struct.unpack(">H", frame[offset:offset+2])[0]
                offset += 2
                bit_names = pmu_cfg["dig_words"][word_idx] if word_idx < len(pmu_cfg["dig_words"]) else [""] * 16
                bits = []
                for bit_idx in range(16):
                    bits.append({
                        "name": bit_names[bit_idx] if bit_idx < len(bit_names) else "",
                        "value": bool(value & (1 << bit_idx)),
                    })
                digitals.append({"value": value, "bits": bits})

            pmus.append({
                "index": pmu_cfg["index"],
                "name": pmu_cfg["name"],
                "id": pmu_cfg["pmu_id"],
                "pmu_flag": pmu_cfg["pmu_flag"],
                "phasor_format": pmu_cfg["phasor_format"],
                "phasor_encoding": pmu_cfg["phasor_encoding"],
                "phasors": phasors,
                "freqs": freqs,
                "dfreqs": dfreqs,
                "analogs": analogs,
                "digital": digitals,
                "stat": pmu_stat,
                "timequality": pmu_tq,
            })

        return {
            "stream_id": stream_id,
            "soc": soc,
            "fracsec": fracsec,
            "time": soc + fracsec / time_base,
            "timestamp": timestamp.isoformat(),
            "leap": leap,
            "crc_ok": recv_crc == calc_crc,
            "pmus": pmus,
            "time_base": time_base,
        }

    except Exception as exc:
        return {"error": str(exc)}


def decode_discrete(frame, config):
    try:
        if len(frame) < 16:
            return {"error": "frame too short"}

        _, _, stream_id = parse_header(frame)
        offset = 14
        pmus = []

        for pmu_cfg in config["pmus"]:
            pmu_words = []
            for word_idx in range(pmu_cfg["dgnmr"]):
                if offset + 2 > len(frame) - 2:
                    return {"error": "incomplete DISCRETE block"}
                value = struct.unpack(">H", frame[offset:offset+2])[0]
                offset += 2
                bit_names = pmu_cfg["dig_words"][word_idx] if word_idx < len(pmu_cfg["dig_words"]) else [""] * 16
                bits = [{"name": bit_names[bit_idx], "value": bool(value & (1 << bit_idx))} for bit_idx in range(16)]
                pmu_words.append({"value": value, "bits": bits})
            pmus.append({"index": pmu_cfg["index"], "name": pmu_cfg["name"], "words": pmu_words})

        return {"stream_id": stream_id, "pmus": pmus}

    except Exception as exc:
        return {"error": str(exc)}


def decode_rename(frame, config):
    try:
        if len(frame) < 16:
            return {"error": "frame too short"}

        offset = 14
        if offset + 2 > len(frame) - 2:
            return {"error": "missing NUM_PMU"}

        num_pmu = struct.unpack(">H", frame[offset:offset+2])[0]
        offset += 2
        updates = []

        for _ in range(num_pmu):
            if offset + 2 > len(frame) - 2:
                break
            pmu_id = struct.unpack(">H", frame[offset:offset+2])[0]
            offset += 2

            pmu_name, consumed = read_name(frame, offset)
            offset += consumed
            pmu_cfg = next((p for p in config["pmus"] if p["pmu_id"] == pmu_id), None)
            if pmu_cfg:
                pmu_cfg["name"] = pmu_name

            ph_names = []
            fr_names = []
            rocof_names = []
            an_names = []
            dig_names = []

            if pmu_cfg:
                for _ in range(pmu_cfg["phnmr"]):
                    ch_name, consumed = read_name(frame, offset)
                    offset += consumed
                    ph_names.append(ch_name)
                for _ in range(pmu_cfg["frnmr"]):
                    ch_name, consumed = read_name(frame, offset)
                    offset += consumed
                    fr_names.append(ch_name)
                for _ in range(pmu_cfg["dfdtnmr"]):
                    ch_name, consumed = read_name(frame, offset)
                    offset += consumed
                    rocof_names.append(ch_name)
                for _ in range(pmu_cfg["annmr"]):
                    ch_name, consumed = read_name(frame, offset)
                    offset += consumed
                    an_names.append(ch_name)
                for _ in range(pmu_cfg["dgnmr"] * 16):
                    ch_name, consumed = read_name(frame, offset)
                    offset += consumed
                    dig_names.append(ch_name)

                if ph_names:
                    pmu_cfg["ph_names"] = ph_names
                if fr_names:
                    pmu_cfg["fr_names"] = fr_names
                if rocof_names:
                    pmu_cfg["rocof_names"] = rocof_names
                if an_names:
                    pmu_cfg["an_names"] = an_names
                if dig_names:
                    pmu_cfg["dig_words"] = [dig_names[i * 16:(i + 1) * 16] for i in range(pmu_cfg["dgnmr"])]

            updates.append({"pmu_id": pmu_id, "name": pmu_name})

        return {"updates": updates, "config": config}

    except Exception as exc:
        return {"error": str(exc)}


def parse_config(frame):
    return decode_config_frame(frame)


def parse_data(frame, config):
    return decode_data(frame, config)
