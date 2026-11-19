//! Level-by-level display for the balanced proof tree.
use std::{
    env,
    io::{self, IsTerminal, Write},
    sync::Mutex,
};

use anyhow::Result;
use clap::builder::styling::{AnsiColor, Style};

use super::resources::ProcessPeaks;

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
    state: Mutex<ProgressState>,
    interactive: bool,
    color: bool,
}

struct ProgressState {
    rows: Vec<Vec<Node>>,
    peak_line: String,
    visible: bool,
}

impl TreeProgress {
    pub fn new(leaves: usize) -> Self {
        let rows: Vec<_> = (0..=leaves.ilog2())
            .map(|level| vec![Node::Waiting; leaves >> level])
            .collect();
        let columns = env::var("COLUMNS")
            .ok()
            .and_then(|s| s.parse::<usize>().ok());
        let terminal = io::stderr().is_terminal() && env::var("TERM").as_deref() != Ok("dumb");
        let interactive =
            terminal && columns.is_none_or(|n| n >= 40.max(16 + position(leaves, 0, leaves - 1)));
        let color = terminal && env::var_os("NO_COLOR").is_none_or(|value| value.is_empty());
        Self {
            state: Mutex::new(ProgressState {
                rows,
                peak_line: ProcessPeaks::default().status_line(),
                visible: false,
            }),
            interactive,
            color,
        }
    }

    pub fn show(&self) {
        let mut state = self.state.lock().unwrap();
        eprintln!("\nProof tree   · waiting   ◇ proving   ● proved   × failed");
        if self.color {
            let [leaf, pair, merge] = [0, 1, 2].map(|level| circuit_style(level, self.color));
            eprintln!(
                "Circuits     {leaf}IMT child{leaf:#}   {pair}First aggregation{pair:#}   {merge}Recursive merge{merge:#}"
            );
        }
        if self.interactive {
            eprint!(
                "{}Proving child proofs\n{}\n",
                tree(&state.rows, self.color),
                state.peak_line
            );
            state.visible = true;
        }
    }

    pub fn update_peaks(&self, peaks: ProcessPeaks) {
        if !self.interactive {
            return;
        }
        let peak_line = peaks.status_line();
        let mut state = self.state.lock().unwrap();
        if state.peak_line == peak_line {
            return;
        }
        state.peak_line = peak_line;
        if state.visible {
            eprintln!("\x1b[1A\r\x1b[2K{}", state.peak_line);
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

    fn update(&self, level: usize, index: usize, node: Node) {
        let mut state = self.state.lock().unwrap();
        state.rows[level][index] = node;
        let rows = &state.rows;
        if self.interactive {
            let action = match node {
                Node::Proving => "Proving",
                Node::Done => "Proved",
                Node::Failed => "Failed",
                Node::Waiting => unreachable!(),
            };
            self.redraw(
                &state,
                &format!(
                    "{action}  {}  {}/{}",
                    label(level, rows.len()),
                    index + 1,
                    rows[level].len()
                ),
            );
        } else if node == Node::Failed
            || (node == Node::Done && rows[level].iter().all(|&n| n == Node::Done))
        {
            eprintln!("{}", row(rows, level, self.color));
        }
    }

    pub fn message(&self, message: &str) {
        let state = self.state.lock().unwrap();
        if self.interactive {
            self.redraw(&state, message);
        } else {
            eprintln!("{message}");
        }
    }

    pub fn finish(&self, peaks: ProcessPeaks) {
        let mut state = self.state.lock().unwrap();
        if self.interactive {
            state.peak_line = peaks.status_line();
            self.redraw(&state, "Root verified");
            state.visible = false;
        } else {
            eprint!("{}", tree(&state.rows, self.color));
            eprintln!("Root verified");
        }
    }

    fn redraw(&self, state: &ProgressState, message: &str) {
        // One row per level, one connector per gap, a phase line and a peak line.
        // The state lock serializes redraws with the sampler.
        let mut out = io::stderr().lock();
        let _ = writeln!(
            out,
            "\x1b[{}A\r{}\x1b[2K{message}\n\x1b[2K{}",
            2 * state.rows.len() + 1,
            tree(&state.rows, self.color),
            state.peak_line
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

fn circuit_style(level: usize, color: bool) -> Style {
    if !color {
        return Style::new();
    }
    match level {
        0 => AnsiColor::Cyan,
        1 => AnsiColor::Yellow,
        _ => AnsiColor::Magenta,
    }
    .on_default()
}

fn row(rows: &[Vec<Node>], level: usize, color: bool) -> String {
    let nodes = &rows[level];
    let leaves = rows[0].len();
    let mut marks = vec![' '; position(leaves, level, nodes.len() - 1) + 1];
    for (index, &node) in nodes.iter().enumerate() {
        marks[position(leaves, level, index)] = node.glyph();
    }
    let done = nodes.iter().filter(|&&n| n == Node::Done).count();
    let style = circuit_style(level, color);
    format!(
        "{style}{:<7} {:>2}/{:<2}  {}{style:#}",
        label(level, rows.len()),
        done,
        nodes.len(),
        marks.into_iter().collect::<String>()
    )
}

fn tree(rows: &[Vec<Node>], color: bool) -> String {
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
        lines.push(row(rows, level, color));
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
        let diagram = tree(&rows, false);
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
            let diagram = tree(&rows, false);
            assert!(diagram.lines().all(|line| line.chars().count() <= 80));
            assert_eq!(diagram.lines().count(), 2 * depth + 1);
        }
    }

    #[test]
    fn colors_follow_circuit_reuse_through_the_root() {
        let rows: Vec<_> = [8, 4, 2, 1].map(|n| vec![Node::Done; n]).into();
        let plain = tree(&rows, false);
        let colored = tree(&rows, true);
        let mut colors = ["\x1b[36m", "\x1b[33m", "\x1b[35m", "\x1b[35m"].into_iter();
        for (i, (line, expected)) in colored.lines().zip(plain.lines()).enumerate() {
            if i % 2 == 0 {
                assert_eq!(line, format!("{}{expected}\x1b[0m", colors.next().unwrap()));
            } else {
                assert_eq!(line, expected);
            }
        }
        assert_eq!(colors.next(), None);
    }

    #[test]
    fn sibling_progress_follows_completion_order() {
        let display = TreeProgress::new(4);
        display.show();
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
            let active = display.state.lock().unwrap().rows[1].clone();
            barrier.wait();
            assert!(first.join().unwrap().is_err());
            assert_eq!(active, [Node::Proving, Node::Done]);
            assert_eq!(
                display.state.lock().unwrap().rows[1],
                [Node::Failed, Node::Done]
            );
        });
    }
}
