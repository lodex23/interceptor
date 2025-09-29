import json
from mitmproxy import http, ctx, addons

class PaymentModifier:
    def __init__(self):
        self.intercepted_once = False

    def load(self, loader):
        loader.add_option(
            name="target_host",
            typespec=str,
            default="",
            help="Only intercept requests to this host (optional).",
        )
        loader.add_option(
            name="target_path_substr",
            typespec=str,
            default="purchase_settings",
        )
        loader.add_option(
            name="json_key",
            typespec=str,
            default="payment_price",
            help="DEPRECATED. Use 'keys' to specify comma-separated keys to modify (json_key kept for backward compatibility).",
        )
        loader.add_option(
            name="json_keys",
            typespec=str,
            default="payment_price,amount,price",
            help="Comma-separated JSON keys to modify (deep, including arrays).",
        )
        loader.add_option(
            name="intercept_once",
            typespec=bool,
            default=True,
            help="If true, only intercept the first matching response.",
        )
        loader.add_option(
            name="modify_all",
            typespec=bool,
            default=False,
            help="If true, modify all occurrences of json_key found in the JSON (deep, including arrays).",
        )
        loader.add_option(
            name="modify_in",
            typespec=str,
            default="response",
            help="Where to modify: 'response', 'request', or 'both'.",
        )
        loader.add_option(
            name="trace",
            typespec=bool,
            default=False,
            help="If true, log matches and chosen edits for debugging.",
        )
        loader.add_option(
            name="addon_log_file",
            typespec=str,
            default="",
            help="If set, write addon logs to this file in addition to mitmdump console.",
        )

    def _should_target(self, flow: http.HTTPFlow) -> bool:
        # Host filter
        target_host = ctx.options.target_host.strip()
        if target_host and flow.request.host != target_host:
            return False
        # Path filter
        if ctx.options.target_path_substr not in flow.request.path:
            return False
        return True

    def _tee_log(self, level: str, msg: str) -> None:
        try:
            if level == "info":
                ctx.log.info(msg)
            elif level == "warn":
                ctx.log.warn(msg)
            else:
                ctx.log.info(msg)
        except Exception:
            pass
        path = getattr(ctx.options, "addon_log_file", "") or ""
        if path:
            try:
                with open(path, "a", encoding="utf-8") as f:
                    f.write(msg + "\n")
            except Exception:
                pass

    def _load_json_text(self, text: str) -> tuple[bool, dict | list | None]:
        try:
            return True, json.loads(text)
        except Exception as e:
            self._tee_log("warn", f"Failed to parse JSON: {e}")
            return False, None

    def _find_matches(self, data, keys):
        matches = []  # tuples: (path_list, parent_container, key_or_index)
        def walk(node, path):
            if isinstance(node, dict):
                for k, v in node.items():
                    if k in keys:
                        matches.append((path + [k], node, k))
                    walk(v, path + [k])
            elif isinstance(node, list):
                for idx, item in enumerate(node):
                    walk(item, path + [idx])
        walk(data, [])
        return matches

    def _modify_json(self, data, where_label: str) -> bool:
        # Determine keys to search
        keys = [k.strip() for k in (ctx.options.json_keys or "").split(",") if k.strip()]
        if not keys:
            keys = [ctx.options.json_key]

        matches = self._find_matches(data, set(keys))
        if not matches:
            if ctx.options.trace:
                self._tee_log("info", f"No matches for keys {keys} in {where_label} body.")
            return False

        if ctx.options.modify_all:
            sample_path, sample_parent, sample_key = matches[0]
            new_val = self._prompt_edit(sample_parent[sample_key], label=self._fmt_path(sample_path) + f" [{where_label}] apply to ALL")
            new_type = type(new_val)
            changed = 0
            skipped = 0
            sample_changed_paths = []
            sample_skipped_paths = []
            for path_list, parent, k_or_i in matches:
                try:
                    cur_val = parent[k_or_i]
                    if type(cur_val) is new_type:
                        parent[k_or_i] = new_val
                        changed += 1
                        if len(sample_changed_paths) < 10:
                            sample_changed_paths.append(self._fmt_path(path_list))
                    else:
                        skipped += 1
                        if len(sample_skipped_paths) < 10:
                            sample_skipped_paths.append(self._fmt_path(path_list) + f" (type {type(cur_val).__name__})")
                except Exception:
                    skipped += 1
            if ctx.options.trace:
                self._tee_log("info", f"Modified {changed} item(s), skipped {skipped} due to type mismatch in {where_label}.")
                if sample_changed_paths:
                    self._tee_log("info", f"Changed paths (sample): {', '.join(sample_changed_paths)}")
                if sample_skipped_paths:
                    self._tee_log("info", f"Skipped paths (sample): {', '.join(sample_skipped_paths)}")
            return changed > 0
        else:
            chosen_idx = 0
            if len(matches) > 1:
                print(f"\nFound {len(matches)} occurrences in {where_label}.")
                for i, (p, parent, k_or_i) in enumerate(matches):
                    try:
                        current_val = parent[k_or_i]
                    except Exception:
                        current_val = "<unreadable>"
                    print(f"[{i}] {self._fmt_path(p)}\n    value={json.dumps(current_val, ensure_ascii=False)}")
                raw = input("Select index to edit (default 0): ").strip()
                if raw.isdigit():
                    chosen_idx = max(0, min(int(raw), len(matches) - 1))
            path, parent, key_or_index = matches[chosen_idx]
            path_str = self._fmt_path(path)
            old_val = parent[key_or_index]
            new_val = self._prompt_edit(old_val, label=path_str + f" [{where_label}]")
            parent[key_or_index] = new_val
            if ctx.options.trace:
                if new_val != old_val:
                    try:
                        old_json = json.dumps(old_val, ensure_ascii=False)
                        new_json = json.dumps(new_val, ensure_ascii=False)
                        self._tee_log("info", f"Edited {where_label}: {path_str}: {old_json} -> {new_json}")
                    except Exception:
                        self._tee_log("info", f"Edited {where_label}: {path_str}: <changed>")
                else:
                    self._tee_log("info", f"Kept original for {where_label}: {path_str}")
            return True

    def _maybe_modify_request(self, flow: http.HTTPFlow) -> bool:
        if ctx.options.modify_in not in ("request", "both"):
            return False
        # Only handle JSON requests
        content_type = flow.request.headers.get("content-type", "").lower()
        text = flow.request.get_text()
        if ("application/json" not in content_type) and (not text.strip().startswith("{")):
            return False
        ok, data = self._load_json_text(text)
        if not ok:
            return False
        changed = self._modify_json(data, where_label="request")
        if changed:
            flow.request.text = json.dumps(data, ensure_ascii=False)
            # Remove encoding and length so mitmproxy recalculates correctly
            flow.request.headers.pop("content-encoding", None)
            flow.request.headers.pop("content-length", None)
            flow.request.headers["content-type"] = "application/json; charset=utf-8"
        return changed

    def _maybe_modify_response(self, flow: http.HTTPFlow) -> bool:
        if ctx.options.modify_in not in ("response", "both"):
            return False
        # Only handle JSON responses
        content_type = flow.response.headers.get("content-type", "").lower()
        text = flow.response.get_text()
        if ("application/json" not in content_type) and (not text.strip().startswith("{")):
            return False
        ok, data = self._load_json_text(text)
        if not ok:
            return False
        changed = self._modify_json(data, where_label="response")
        if changed:
            flow.response.text = json.dumps(data, ensure_ascii=False)
            # Remove encoding and length so mitmproxy recalculates and sends plain text JSON
            flow.response.headers.pop("content-encoding", None)
            flow.response.headers.pop("content-length", None)
            flow.response.headers["content-type"] = "application/json; charset=utf-8"
        return changed

    def request(self, flow: http.HTTPFlow) -> None:
        if not self._should_target(flow):
            return
        if ctx.options.intercept_once and self.intercepted_once:
            return
        if self._maybe_modify_request(flow):
            self.intercepted_once = True

    def response(self, flow: http.HTTPFlow) -> None:
        if not self._should_target(flow):
            return
        if ctx.options.intercept_once and self.intercepted_once:
            return
        if self._maybe_modify_response(flow):
            self.intercepted_once = True

    def _prompt_edit(self, obj, label: str):
        self._tee_log("info", "=== Intercepted response. Allowing manual edit. ===")
        print("\n==============================")
        print(f"Editing field: {label}")
        print("Current value:")
        print(json.dumps(obj, indent=2, ensure_ascii=False))
        print("------------------------------")
        print("Instructions:")
        print("- Press Enter to accept current value")
        print("- Paste new JSON for this field. IMPORTANT: keep the same type as current value.")
        print("  * If current is a number, input a number (e.g., 0.01)")
        print("  * If current is an object, input an object (e.g., {\"price\":0.01,\"currency\":\"eur\"})")
        print("==============================\n")
        user_input = input("New JSON (blank to keep): ").strip()
        if not user_input:
            return obj
        try:
            new_obj = json.loads(user_input)
            if type(new_obj) is not type(obj):
                print(f"Type mismatch: expected {type(obj).__name__}, got {type(new_obj).__name__}. Keeping original to avoid breaking the page.")
                return obj
            return new_obj
        except Exception as e:
            print(f"Invalid JSON, keeping original. Error: {e}")
            return obj

    def _fmt_path(self, path_list):
        out = []
        for p in path_list:
            if isinstance(p, int):
                out.append(f"[{p}]")
            else:
                if out:
                    out.append(".")
                out.append(p)
        return "".join(out)

addons = [PaymentModifier()]