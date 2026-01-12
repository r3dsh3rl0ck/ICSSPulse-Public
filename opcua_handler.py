from opcua import Client, ua
from opcua.ua.uaerrors import UaStatusCodeError
import socket

def _build_endpoint(target: str, port: int, path: str) -> str:
    path = (path or "").strip("/")
    return f"opc.tcp://{target}:{port}/" + (f"{path}/" if path else "")

def _booly(s):
    if isinstance(s, bool):
        return s
    if s is None:
        return False
    s = str(s).strip().lower()
    return s in {"1", "true", "t", "yes", "y", "on"}

def _cast_for_variant(datatype: ua.VariantType, value_str: str):
    if datatype in (ua.VariantType.Boolean,):
        return _booly(value_str)
    if datatype in (ua.VariantType.SByte, ua.VariantType.Byte,
                    ua.VariantType.Int16, ua.VariantType.UInt16,
                    ua.VariantType.Int32, ua.VariantType.UInt32,
                    ua.VariantType.Int64, ua.VariantType.UInt64):
        return int(value_str)
    if datatype in (ua.VariantType.Float, ua.VariantType.Double):
        return float(value_str)
    if datatype in (ua.VariantType.String,):
        return str(value_str)
    # Fallback
    try:
        return int(value_str)
    except Exception:
        try:
            return float(value_str)
        except Exception:
            return str(value_str)

def _enum_name(enum_cls, value):
    try:
        return enum_cls(value).name
    except Exception:
        # python-opcua sometimes stores already as enum; try .name
        try:
            return getattr(value, "name")
        except Exception:
            return str(value)

def _format_endpoint(ep):
    toks = []
    toks.append(f"EndpointUrl: {getattr(ep, 'EndpointUrl', 'n/a')}")
    toks.append(f"SecurityPolicyUri: {getattr(ep, 'SecurityPolicyUri', 'n/a')}")
    mode = _enum_name(ua.MessageSecurityMode, getattr(ep, 'SecurityMode', None))
    toks.append(f"SecurityMode: {mode}")
    toks.append("UserIdentityTokens:")
    for t in getattr(ep, 'UserIdentityTokens', []) or []:
        try:
            tok = _enum_name(ua.UserTokenType, t.TokenType)
        except Exception:
            tok = str(getattr(t, 'TokenType', 'Unknown'))
        issued = getattr(t, 'IssuedTokenType', None) or 'n/a'
        toks.append(f"  - {tok} ({issued})")
    return "\n".join(toks)

def _safe_set_timeout(client: Client, timeout_s: int):
    try:
        client.session_timeout = max(10000, timeout_s * 1000)
    except Exception:
        pass
    try:
        client.set_timeout(timeout_s * 1000)
    except Exception:
        pass
    try:
        socket.setdefaulttimeout(timeout_s)
    except Exception:
        pass

def _browse_recursive(node, depth, max_depth, out_lines, visited, budget):
    if depth > max_depth or budget[0] <= 0:
        return
    try:
        nodeid_s = node.nodeid.to_string()
        if nodeid_s in visited:
            return
        visited.add(nodeid_s)

        try:
            bname = node.get_browse_name()
            bname_str = f"{bname.NamespaceIndex}:{bname.Name}"
        except Exception:
            bname_str = "?:?"

        try:
            dname = node.get_display_name().Text
        except Exception:
            dname = ""

        try:
            nclass = node.get_node_class()
            nclass_s = _enum_name(ua.NodeClass, nclass)
        except Exception:
            nclass_s = "Unknown"

        out_lines.append(f"[{nclass_s}] {nodeid_s}  BrowseName={bname_str}  DisplayName={dname}")
        budget[0] -= 1

        try:
            for ch in node.get_children():
                if budget[0] <= 0:
                    break
                _browse_recursive(ch, depth + 1, max_depth, out_lines, visited, budget)
        except Exception:
            pass
    except Exception as e:
        out_lines.append(f"Browse error at depth {depth}: {e}")

def handle_opcua(args):
    """
    Expected args (from Flask form):
        protocol == 'opcua'
        action: discover | browse | enumerate | read | write
        target, port (default 4840), endpoint_path (default 'freeopcua/server/')
        username, password (optional)
        nodeid (for read/write), value (for write)
        max_depth (browse), max_nodes (browse/enumerate), namespace (enumerate filter)
        timeout, retries
    """
    output = ''
    success = False

    endpoint = _build_endpoint(args.target, int(getattr(args, 'port', 4840)), getattr(args, 'endpoint_path', 'freeopcua/server/'))
    timeout = int(getattr(args, 'timeout', 3))
    retries = int(getattr(args, 'retries', 3))
    username = getattr(args, 'username', '') or None
    password = getattr(args, 'password', '') or None

    for attempt in range(1, retries + 1):
        try:
            if args.action == 'discover':
                c = Client(endpoint)
                _safe_set_timeout(c, timeout)
                endpoints = c.connect_and_get_server_endpoints()
                try:
                    c.disconnect()
                except Exception:
                    pass
                if not endpoints:
                    output += "No endpoints returned by server.\n"
                else:
                    output += f"Discovered {len(endpoints)} endpoint(s):\n"
                    for idx, ep in enumerate(endpoints, 1):
                        output += f"\n--- Endpoint {idx} ---\n{_format_endpoint(ep)}\n"
                success = True
                break

            client = Client(endpoint)
            _safe_set_timeout(client, timeout)

            # Credentials if provided, else Anonymous
            if username:
                client.set_user(username)
                client.set_password(password or "")
            else:
                client.set_user("")  # Anonymous/empty

            client.connect()

            # Namespace array
            try:
                ns_array = client.get_node(ua.ObjectIds.Server_NamespaceArray).get_value()
            except Exception:
                ns_array = []
            if ns_array:
                output += "NamespaceArray:\n"
                for i, uri in enumerate(ns_array):
                    output += f"  ns[{i}] = {uri}\n"
                output += "\n"

            if args.action == 'browse':
                objects = client.get_objects_node()
                output += f"Objects: {objects.nodeid}\n\n"
                max_depth = int(getattr(args, 'max_depth', 3))
                max_nodes = int(getattr(args, 'max_nodes', 200))
                lines, visited, budget = [], set(), [max_nodes]
                _browse_recursive(objects, 0, max_depth, lines, visited, budget)
                output += ("\n".join(lines) + "\n") if lines else "No nodes found (or budget exhausted).\n"
                success = True

            elif args.action == 'enumerate':
                ns_filter = getattr(args, 'namespace', None)
                try:
                    ns_filter = int(ns_filter) if ns_filter not in (None, '') else None
                except Exception:
                    ns_filter = None

                objects = client.get_objects_node()
                max_depth = int(getattr(args, 'max_depth', 4))
                max_nodes = int(getattr(args, 'max_nodes', 400))
                lines, visited, budget = [], set(), [max_nodes]

                stack = [(objects, 0)]
                while stack and budget[0] > 0:
                    node, d = stack.pop()
                    if d > max_depth:
                        continue
                    nid = node.nodeid
                    nid_s = nid.to_string()
                    if nid_s in visited:
                        continue
                    visited.add(nid_s)

                    try:
                        for ch in node.get_children():
                            stack.append((ch, d + 1))
                    except Exception:
                        pass

                    try:
                        if node.get_node_class() == ua.NodeClass.Variable:
                            if (ns_filter is None) or (nid.NamespaceIndex == ns_filter):
                                try:
                                    bname = node.get_browse_name()
                                    bname_s = f"{bname.NamespaceIndex}:{bname.Name}"
                                except Exception:
                                    bname_s = "?:?"
                                try:
                                    dname = node.get_display_name().Text
                                except Exception:
                                    dname = ""
                                try:
                                    vtype = node.get_data_type_as_variant_type()
                                    vtype_s = _enum_name(ua.VariantType, vtype)
                                except Exception:
                                    vtype_s = "Unknown"
                                try:
                                    al = node.get_attribute(ua.AttributeIds.AccessLevel).Value.Value
                                    user_al = node.get_attribute(ua.AttributeIds.UserAccessLevel).Value.Value
                                except Exception:
                                    al = user_al = 0
                                try:
                                    val = node.get_value()
                                except Exception as e:
                                    val = f"<read error: {e}>"

                                lines.append(
                                    f"{nid_s}  BrowseName={bname_s}  DisplayName={dname}  "
                                    f"DataType={vtype_s}  Access={al} UserAccess={user_al}  Value={val}"
                                )
                                budget[0] -= 1
                    except Exception as e:
                        lines.append(f"Enumerate error: {e}")
                        budget[0] -= 1

                output += ("\n".join(lines) + "\n") if lines else "No variables found.\n"
                success = True

            elif args.action == 'read':
                nodeid = getattr(args, 'nodeid', None)
                if not nodeid:
                    output += "Error: 'read' requires a NodeId (e.g., ns=2;i=10).\n"
                else:
                    node = client.get_node(str(nodeid))
                    val = node.get_value()
                    output += f"Read {nodeid}: {val}\n"
                    success = True

            elif args.action == 'write':
                nodeid = getattr(args, 'nodeid', None)
                if not nodeid:
                    output += "Error: 'write' requires a NodeId and value.\n"
                else:
                    node = client.get_node(str(nodeid))
                    vtype = node.get_data_type_as_variant_type()
                    py_val = _cast_for_variant(vtype, getattr(args, 'value', ''))
                    node.set_value(ua.Variant(py_val, vtype))
                    new_val = node.get_value()
                    output += f"Write OK. {nodeid} <= {py_val}  (now: {new_val})\n"
                    success = True

            else:
                output += f"Unsupported action: {args.action}\n"

            try:
                client.disconnect()
            except Exception:
                pass

            if success:
                break

        except (UaStatusCodeError, ConnectionError, OSError, socket.timeout, Exception) as e:
            output += f"Attempt {attempt} failed: {e}\n"

    if not success:
        output += "All retries failed.\n"
    elif not output:
        output = "Operation completed with no output."

    return output
