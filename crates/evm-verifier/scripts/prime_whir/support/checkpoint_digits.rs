pub fn checkpoint(input: &[u8; 200], row: &mut [u8]) -> ([u8; 200], [u8; 200]) {
    let mut mid = [0; 200];
    let mut end = [0; 200];
    super::segments::visit_states(input, None, |segment, state| {
        if segment == 4 {
            mid = *state;
        }
        if segment == 8 {
            end = *state;
        }
        for lane in 0..25 {
            let (s, l) = if segment == 8 {
                (lane / 7, 25 + lane % 7)
            } else {
                (segment, lane)
            };
            let slot = (s * 32 + l) * 16;
            for i in 0..8 {
                let v = state[8 * lane + i];
                row[slot + 2 * i] = v & 15;
                row[slot + 2 * i + 1] = v >> 4;
            }
        }
    });
    (mid, end)
}
