configs = {}
time_bases = {}
cfg_frag_bufs = {}

def _make_key(conn_key, stream_id):
    if conn_key:
        return f"{conn_key}:{stream_id}"
    return str(stream_id)


def store_config(new_config, new_cfgcnt, conn_key, stream_id):
    key = _make_key(conn_key, stream_id)
    configs[key] = new_config
    time_bases[key] = new_config.get("time_base")
    print(f"CONFIG stored for {key}")


def get_config(conn_key, stream_id):
    return configs.get(_make_key(conn_key, stream_id))


def has_config(conn_key, stream_id):
    return _make_key(conn_key, stream_id) in configs


def append_config_fragment(conn_key, stream_id, payload):
    key = _make_key(conn_key, stream_id)
    if key not in cfg_frag_bufs:
        cfg_frag_bufs[key] = bytearray()
    cfg_frag_bufs[key].extend(payload)


def get_config_fragment(conn_key, stream_id):
    return cfg_frag_bufs.get(_make_key(conn_key, stream_id))


def clear_config_fragment(conn_key, stream_id):
    cfg_frag_bufs.pop(_make_key(conn_key, stream_id), None)
