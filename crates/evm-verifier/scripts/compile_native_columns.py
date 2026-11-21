"""Encode the trusted 64-client column-opening schedule for the Solidity verifier."""


def aligned_blocks(slot, width, rows, arity, used_cells):
    # Each column occupies a consecutive slot. Only the final table may pad a
    # block past its width, into unallocated cells of the committed polynomial.
    end = slot + width
    free_tail = (end << rows) == used_cells
    position = slot
    while position < end:
        variables = (width - 1).bit_length()
        if position:
            variables = min(variables, (position & -position).bit_length() - 1)
        limit = (1 << (arity - rows)) if free_tail else end
        while position + (1 << variables) > limit:
            variables -= 1
        yield arity - rows - variables, position >> variables, variables, position - slot
        position += 1 << variables


def compile_columns(key):
    output = bytearray()
    claims = 0
    value_count = 0
    for face, name in enumerate(("main", "fixed")):
        heights = list(key["heights"])
        if face:
            heights = [h for h, w in zip(heights, key["fixed_widths"], strict=True) if w]
        else:
            heights.extend(t.get("height", 27) for t in key[name][len(heights):])
        tables = key[name]
        rows = [height + len(t["suffix"]) for height, t in zip(heights, tables, strict=True)]
        used = sum(t["committed"] << r for t, r in zip(tables, rows, strict=True))
        arity = (used - 1).bit_length()
        if arity != 31 - face:
            raise ValueError("unknown stacked terminal shape")
        next_aux = 1
        for i, (t, r, height) in enumerate(zip(tables, rows, heights, strict=True)):
            width = t["committed"]
            blocks = list(aligned_blocks(t["slot"], width, r, arity, used))
            aux = face == 0 and i >= len(key["heights"])
            for batch in range(t.get("batches", 2 if aux else 1)):
                source = next_aux if aux else 0
                next_aux += int(aux)
                domain = bytes.fromhex(t["domain"]) if batch == 0 else b""
                output.extend(
                    bytes([face, source, height, len(t["suffix"]), (width - 1).bit_length(), len(blocks)])
                )
                output.extend(width.to_bytes(2, "big") + len(domain).to_bytes(2, "big"))
                output.extend(domain)
                for coordinate in t["suffix"]:
                    output.extend(coordinate.to_bytes(8, "little"))
                for size, prefix, variables, first in blocks:
                    output.extend(
                        bytes([size, variables]) + first.to_bytes(2, "big") + prefix.to_bytes(4, "big")
                    )
                claims += len(blocks)
                value_count += width
    if claims != 134 or value_count not in (2070, 2071):
        raise ValueError("incorrect number of native bit claims or evaluations")
    return bytes(output)
