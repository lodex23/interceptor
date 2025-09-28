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
            help="Substring that must be present in the request path to intercept.",
        )
        loader.add_option(
            name="json_key",
            typespec=str,
            default="payment_price",
            help="JSON key in the response to modify.",
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

    def response(self, flow: http.HTTPFlow) -> None:
        # Host filter
        target_host = ctx.options.target_host.strip()
        if target_host and flow.request.host != target_host:
{{ ... }}

        except Exception as e:
            ctx.log.warn(f"Failed to parse JSON: {e}")
            return

        key = ctx.options.json_key

        # Deep search for all occurrences of the key (dicts + lists)
        matches = []  # list of tuples: (path_list, parent_container, key_or_index)

        def walk(node, path):
            if isinstance(node, dict):
                for k, v in node.items():
                    if k == key:
                        matches.append((path + [k], node, k))
                    walk(v, path + [k])
            elif isinstance(node, list):
                for idx, item in enumerate(node):
                    walk(item, path + [idx])

        walk(data, [])

        if not matches:
            return

        if ctx.options.modify_all and matches:
            # Prompt once using the first match as example, then apply to all
            sample_path, sample_parent, sample_key = matches[0]
            new_val = self._prompt_edit(
                sample_parent[sample_key], label=self._fmt_path(sample_path) + " (apply to ALL matches)"
            )
            for _, parent, k_or_i in matches:
                parent[k_or_i] = new_val
            ctx.log.info(f"Modified {len(matches)} occurrence(s) of '{key}'.")
        else:
            # Let user choose which one to edit when multiple are found
            chosen_idx = 0
            if len(matches) > 1:
                print(f"\nFound {len(matches)} occurrences of '{key}'.")
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
            parent[key_or_index] = self._prompt_edit(parent[key_or_index], label=self._fmt_path(path))

        # Update response with modified data
        flow.response.text = json.dumps(data)
        flow.response.headers["content-length"] = str(len(flow.response.text.encode("utf-8")))
        self.intercepted_once = True
{{ ... }}
                    out.append(".")
                out.append(p)
        return "".join(out)

addons = [PaymentModifier()]
