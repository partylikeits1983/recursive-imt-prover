use std::{
    cmp::Reverse,
    collections::BinaryHeap,
    panic::{AssertUnwindSafe, catch_unwind, resume_unwind},
    sync::mpsc,
    time::Instant,
};

use anyhow::{Result, ensure};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Limits {
    pub jobs: usize,
    pub leaves: usize,
    pub aggregates: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Node {
    pub level: usize,
    pub index: usize,
}

pub(super) enum Input<L, P> {
    Leaf(L),
    Pair([P; 2]),
}

pub(super) fn run<L: Send, P: Send>(
    leaves: Vec<L>,
    limits: Limits,
    prove: impl Fn(Node, Input<L, P>) -> Result<P> + Sync,
    mut record: impl FnMut(Node, &P, Instant, Instant),
) -> Result<P> {
    let leaf_count = leaves.len();
    let depth = leaf_count.ilog2();
    let mut leaves = (leaf_count..).zip(leaves);

    // Heap numbering puts the root at 1, leaves at leaf_count, and every
    // parent at half its children's index. Smaller IDs are closer to the root.
    let mut completed: Vec<Option<P>> = (0..2 * leaf_count).map(|_| None).collect();
    let mut ready: BinaryHeap<Reverse<usize>> = BinaryHeap::new();
    let mut active_leaves = 0;
    let mut active_aggregates = 0;
    let (send, receive) = mpsc::channel();
    let prove = &prove;

    // The coordinator stays off the Rayon pool so even --threads 1 can make progress.
    rayon::in_place_scope(|scope| {
        loop {
            while active_leaves + active_aggregates < limits.jobs {
                let (id, input) = if active_aggregates < limits.aggregates
                    && let Some(Reverse(id)) = ready.pop()
                {
                    active_aggregates += 1;
                    let inputs = [
                        completed[2 * id].take().unwrap(),
                        completed[2 * id + 1].take().unwrap(),
                    ];
                    (id, Input::Pair(inputs))
                } else if active_leaves < limits.leaves
                    && let Some((id, leaf)) = leaves.next()
                {
                    active_leaves += 1;
                    (id, Input::Leaf(leaf))
                } else {
                    break;
                };
                let node = Node {
                    level: (depth - id.ilog2()) as usize,
                    index: id - (1 << id.ilog2()),
                };
                let send = send.clone();
                scope.spawn(move |_| {
                    let started = Instant::now();
                    // Wake the coordinator on a panic as well as on a normal completion.
                    let result = catch_unwind(AssertUnwindSafe(|| prove(node, input)));
                    let _ = send.send((id, node, started, Instant::now(), result));
                });
            }

            ensure!(
                active_leaves + active_aggregates > 0,
                "proof scheduler stalled"
            );
            let (id, node, started, finished, result) = receive.recv()?;
            let proof = match result {
                Ok(result) => result?,
                Err(panic) => resume_unwind(panic),
            };
            record(node, &proof, started, finished);
            if id == 1 {
                return Ok(proof);
            }
            if node.level == 0 {
                active_leaves -= 1;
            } else {
                active_aggregates -= 1;
            }
            completed[id] = Some(proof);
            if completed[id ^ 1].is_some() {
                ready.push(Reverse(id / 2));
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use std::{
        sync::{Mutex, mpsc},
        thread,
        time::Duration,
    };

    use super::{Input, Limits, Node, run};

    #[test]
    fn fills_slots_across_levels_and_prefers_ready_parents() {
        const WAIT: Duration = Duration::from_secs(5);
        rayon::ThreadPoolBuilder::new()
            .num_threads(3)
            .build_global()
            .unwrap();
        thread::scope(|scope| {
            let levels: Vec<Vec<_>> = (0..=3)
                .map(|level| (0..8 >> level).map(|_| mpsc::channel::<()>()).collect())
                .collect();
            let (releases, gates): (Vec<Vec<_>>, Vec<Vec<_>>) = levels
                .into_iter()
                .map(|level| {
                    level
                        .into_iter()
                        .map(|(release, gate)| (release, Mutex::new(gate)))
                        .unzip()
                })
                .unzip();
            let (started, events) = mpsc::channel();
            let worker = scope.spawn(move || {
                run::<usize, Vec<usize>>(
                    (0..8).collect(),
                    Limits {
                        jobs: 3,
                        leaves: 3,
                        aggregates: 3,
                    },
                    |node, input| {
                        started.send(node)?;
                        gates[node.level][node.index]
                            .lock()
                            .unwrap()
                            .recv_timeout(WAIT)?;
                        Ok(match input {
                            Input::Leaf(index) => vec![index],
                            Input::Pair([mut left, right]) => {
                                left.extend(right);
                                left
                            }
                        })
                    },
                    |_, _, _, _| {},
                )
            });
            let started = || events.recv_timeout(WAIT).unwrap();
            let release = |level: usize, index: usize| releases[level][index].send(()).unwrap();
            let mut initial = [started(), started(), started()];
            initial.sort_unstable_by_key(|node| node.index);
            assert_eq!(initial, [0, 1, 2].map(|index| Node { level: 0, index }));
            let advance = |done_level, done_index, next_level, next_index| {
                release(done_level, done_index);
                assert_eq!(
                    started(),
                    Node {
                        level: next_level,
                        index: next_index
                    }
                );
            };
            advance(0, 0, 0, 3);
            advance(0, 1, 1, 0);
            advance(0, 2, 0, 4);
            advance(0, 3, 1, 1);
            advance(0, 4, 0, 5);
            advance(1, 0, 0, 6);
            advance(1, 1, 2, 0);
            advance(0, 5, 1, 2);
            advance(0, 6, 0, 7);
            advance(0, 7, 1, 3);
            release(1, 3);
            advance(1, 2, 2, 1);
            release(2, 1);
            advance(2, 0, 3, 0);
            release(3, 0);
            assert_eq!(worker.join().unwrap().unwrap(), (0..8).collect::<Vec<_>>());
        });
    }
}
