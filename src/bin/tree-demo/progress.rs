//! Level-by-level display for the balanced proof tree.
use std::{
    env,
    io::{self, IsTerminal, Write},
    sync::Mutex,
};

use anyhow::Result;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Node {
    Waiting,
    Proving,
    Done,
    Failed,
}

impl Node {
    fn glyph(self) -> char {
        match self {
            Self::Waiting => '·',
            Self::Proving => '◇',
            Self::Done => '●',
            Self::Failed => '×',
        }
    }
}

pub(super) struct TreeProgress {
    rows: Mutex<Vec<Vec<Node>>>,
    interactive: bool,
}

impl TreeProgress {
    pub fn new(leaves: usize) -> Self {
        let rows: Vec<_> = (0..=leaves.ilog2())
            .map(|level| vec![Node::Waiting; leaves >> level])
            .collect();
        let columns = env::var("COLUMNS")
            .ok()
            .and_then(|s| s.parse::<usize>().ok());
        let interactive = io::stderr().is_terminal()
            && env::var("TERM").as_deref() != Ok("dumb")
            && columns.is_none_or(|n| n >= 40.max(16 + position(leaves, 0, leaves - 1)));
        eprintln!("\nProof tree   · waiting   ◇ proving   ● proved   × failed");
        if interactive {
            eprint!("{}", tree(&rows));
            eprintln!("Proving child proofs");
        }
        Self {
            rows: Mutex::new(rows),
            interactive,
        }
    }

    pub fn track<T>(
        &self,
        level: usize,
        index: usize,
        prove: impl FnOnce() -> Result<T>,
    ) -> Result<T> {
        self.update(level, index, Node::Proving);
        let result = prove();
        self.update(
            level,
            index,
            if result.is_ok() {
                Node::Done
            } else {
                Node::Failed
            },
        );
        result
    }

    fn update(&self, level: usize, index: usize, state: Node) {
        let mut rows = self.rows.lock().unwrap();
        rows[level][index] = state;
        if self.interactive {
            let action = match state {
                Node::Proving => "Proving",
                Node::Done => "Proved",
                Node::Failed => "Failed",
                Node::Waiting => unreachable!(),
            };
            self.redraw(
                &rows,
                &format!(
                    "{action}  {}  {}/{}",
                    label(level, rows.len()),
                    index + 1,
                    rows[level].len()
                ),
            );
        } else if state == Node::Failed
            || (state == Node::Done && rows[level].iter().all(|&n| n == Node::Done))
        {
            eprintln!("{}", row(&rows, level));
        }
    }

    pub fn message(&self, message: &str) {
        let rows = self.rows.lock().unwrap();
        if self.interactive {
            self.redraw(&rows, message);
        } else {
            eprintln!("{message}");
        }
    }

    pub fn finish(&self) {
        if !self.interactive {
            eprint!("{}", tree(&self.rows.lock().unwrap()));
        }
        self.message("Root verified");
    }

    fn redraw(&self, rows: &[Vec<Node>], message: &str) {
        // One row per level, one connector per gap and a phase line. A single
        // locked write keeps concurrent sibling completions in display order.
        let mut out = io::stderr().lock();
        let _ = writeln!(
            out,
            "\x1b[{}A\r{}\x1b[2K{message}",
            2 * rows.len(),
            tree(rows)
        );
    }
}

fn label(level: usize, levels: usize) -> String {
    match level {
        0 => "Leaves".into(),
        1 => "Pairs".into(),
        n if n + 1 == levels => "Root".into(),
        n => format!("Merge {}", n - 1),
    }
}

fn position(leaves: usize, level: usize, index: usize) -> usize {
    // Keep a 64-leaf tree within 80 terminal columns. Smaller trees have
    // room to center a parent glyph between its two children.
    let spacing = if leaves == 64 { 1 } else { 2 };
    let span = 1 << level;
    index * span * spacing + (span - 1) * spacing / 2
}

fn row(rows: &[Vec<Node>], level: usize) -> String {
    let nodes = &rows[level];
    let leaves = rows[0].len();
    let mut marks = vec![' '; position(leaves, level, nodes.len() - 1) + 1];
    for (index, &node) in nodes.iter().enumerate() {
        marks[position(leaves, level, index)] = node.glyph();
    }
    let done = nodes.iter().filter(|&&n| n == Node::Done).count();
    format!(
        "{:<7} {:>2}/{:<2}  {}",
        label(level, rows.len()),
        done,
        nodes.len(),
        marks.into_iter().collect::<String>()
    )
}

fn tree(rows: &[Vec<Node>]) -> String {
    let leaves = rows[0].len();
    let mut lines = Vec::new();
    for level in 0..rows.len() {
        if level > 0 {
            let mut edges = vec![' '; position(leaves, level - 1, rows[level - 1].len() - 1) + 1];
            for i in 0..rows[level].len() {
                let left = position(leaves, level - 1, 2 * i);
                let right = position(leaves, level - 1, 2 * i + 1);
                edges[left] = '└';
                edges[left + 1..right].fill('─');
                edges[right] = '┘';
                let parent = position(leaves, level, i);
                if parent > left {
                    edges[parent] = '┬';
                } else {
                    edges[left] = '├';
                }
            }
            lines.push(format!(
                "{:15}{}",
                "",
                edges.into_iter().collect::<String>()
            ));
        }
        lines.push(row(rows, level));
    }
    lines.push(String::new());
    lines.join("\n")
}

#[cfg(test)]
mod tests {
    use std::{sync::Barrier, thread};

    use super::{Node, TreeProgress, tree};

    #[test]
    fn four_leaves_show_both_siblings_and_their_parent() {
        let rows = vec![
            vec![Node::Done; 4],
            vec![Node::Proving, Node::Done],
            vec![Node::Waiting],
        ];
        let diagram = tree(&rows);
        assert_eq!(
            diagram.lines().collect::<Vec<_>>(),
            [
                "Leaves   4/4   ● ● ● ●",
                "               └┬┘ └┬┘",
                "Pairs    1/2    ◇   ●",
                "                └─┬─┘",
                "Root     0/1      ·",
            ]
        );
    }

    #[test]
    fn all_supported_sizes_fit_eighty_columns() {
        for depth in 2..=6 {
            let rows: Vec<_> = (0..=depth)
                .map(|i| vec![Node::Waiting; 1 << (depth - i)])
                .collect();
            let diagram = tree(&rows);
            assert!(diagram.lines().all(|line| line.chars().count() <= 80));
            assert_eq!(diagram.lines().count(), 2 * depth + 1);
        }
    }

    #[test]
    fn sibling_progress_follows_completion_order() {
        let display = TreeProgress::new(4);
        let barrier = Barrier::new(2);
        thread::scope(|scope| {
            let first = scope.spawn(|| {
                display.track(1, 0, || -> anyhow::Result<()> {
                    barrier.wait();
                    barrier.wait();
                    anyhow::bail!("failed sibling")
                })
            });
            barrier.wait();
            display.track(1, 1, || Ok(())).unwrap();
            let active = display.rows.lock().unwrap()[1].clone();
            barrier.wait();
            assert!(first.join().unwrap().is_err());
            assert_eq!(active, [Node::Proving, Node::Done]);
            assert_eq!(display.rows.lock().unwrap()[1], [Node::Failed, Node::Done]);
        });
    }
}
