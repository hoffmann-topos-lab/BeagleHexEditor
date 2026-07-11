use std::path::{Path, PathBuf};

use crate::error::{Error, ErrorKind, Result};

const HEADER: &str = "# hexed bookmarks v1";
/// Sidecar file suffix: `firmware.bin` → `firmware.bin.hexed-bookmarks`.
pub const SIDECAR_SUFFIX: &str = ".hexed-bookmarks";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bookmark {
    pub offset: u64,
    /// Size of the marked region; 0 = a position only.
    pub len: u64,
    pub name: String,
    pub description: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Bookmarks {
    items: Vec<Bookmark>,
}

impl Bookmarks {
    pub fn new() -> Self {
        Self::default()
    }

    /// The sidecar file path of a document.
    pub fn sidecar_for(doc_path: &Path) -> PathBuf {
        let mut os = doc_path.as_os_str().to_os_string();
        os.push(SIDECAR_SUFFIX);
        PathBuf::from(os)
    }

    /// Loads the sidecar file. A missing file is an empty list — having no
    /// bookmarks is not an error.
    pub fn load(path: &Path) -> Result<Self> {
        let text = match std::fs::read_to_string(path) {
            Ok(t) => t,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Self::new()),
            Err(e) => return Err(e.into()),
        };
        let mut items = Vec::new();
        for (n, line) in text.lines().enumerate() {
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let mut fields = line.split('\t');
            let parse = |s: Option<&str>| -> Result<u64> {
                let s = s.ok_or_else(|| {
                    Error::new(ErrorKind::Io, format!("malformed line {}", n + 1))
                })?;
                let r = match s.strip_prefix("0x") {
                    Some(h) => u64::from_str_radix(h, 16),
                    None => s.parse(),
                };
                r.map_err(|_| {
                    Error::new(ErrorKind::Io, format!("invalid number on line {}", n + 1))
                })
            };
            let offset = parse(fields.next())?;
            let len = parse(fields.next())?;
            let name = unescape(fields.next().unwrap_or(""));
            let description = unescape(fields.next().unwrap_or(""));
            items.push(Bookmark { offset, len, name, description });
        }
        Ok(Self { items })
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        let mut out = String::from(HEADER);
        out.push('\n');
        for b in &self.items {
            out.push_str(&format!(
                "{:#x}\t{}\t{}\t{}\n",
                b.offset,
                b.len,
                escape(&b.name),
                escape(&b.description)
            ));
        }
        std::fs::write(path, out)?;
        Ok(())
    }

    /// Inserts while keeping the list sorted by offset.
    pub fn add(&mut self, bookmark: Bookmark) {
        let at = self.items.partition_point(|b| b.offset <= bookmark.offset);
        self.items.insert(at, bookmark);
    }

    pub fn remove(&mut self, index: usize) -> Option<Bookmark> {
        (index < self.items.len()).then(|| self.items.remove(index))
    }

    pub fn items(&self) -> &[Bookmark] {
        &self.items
    }

    pub fn len(&self) -> usize {
        self.items.len()
    }

    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }
}

fn escape(s: &str) -> String {
    s.chars()
        .flat_map(|c| match c {
            '\\' => vec!['\\', '\\'],
            '\t' => vec!['\\', 't'],
            '\n' => vec!['\\', 'n'],
            c => vec![c],
        })
        .collect()
}

fn unescape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        match chars.next() {
            Some('t') => out.push('\t'),
            Some('n') => out.push('\n'),
            Some(c) => out.push(c),
            None => out.push('\\'),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bm(offset: u64, name: &str) -> Bookmark {
        Bookmark { offset, len: 4, name: name.into(), description: String::new() }
    }

    #[test]
    fn roundtrip_through_the_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("doc.bin.hexed-bookmarks");

        let mut marks = Bookmarks::new();
        marks.add(Bookmark {
            offset: 0x40,
            len: 16,
            name: "header".into(),
            description: "magic + version".into(),
        });
        marks.add(bm(0, "start"));
        marks.save(&path).unwrap();

        let loaded = Bookmarks::load(&path).unwrap();
        assert_eq!(loaded, marks);
    }

    #[test]
    fn a_missing_file_is_an_empty_list() {
        let loaded = Bookmarks::load(Path::new("/does/not/exist/at/all")).unwrap();
        assert!(loaded.is_empty());
    }

    #[test]
    fn add_keeps_the_offset_order() {
        let mut marks = Bookmarks::new();
        marks.add(bm(100, "b"));
        marks.add(bm(10, "a"));
        marks.add(bm(50, "middle"));
        let offsets: Vec<u64> = marks.items().iter().map(|b| b.offset).collect();
        assert_eq!(offsets, vec![10, 50, 100]);
        marks.remove(1);
        assert_eq!(marks.len(), 2);
        assert_eq!(marks.items()[1].name, "b");
    }

    #[test]
    fn names_with_tabs_and_newlines_survive() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("x.hexed-bookmarks");
        let mut marks = Bookmarks::new();
        marks.add(Bookmark {
            offset: 1,
            len: 0,
            name: "with\ttab".into(),
            description: "two\nlines \\ backslash".into(),
        });
        marks.save(&path).unwrap();
        assert_eq!(Bookmarks::load(&path).unwrap(), marks);
    }

    #[test]
    fn the_sidecar_appends_the_suffix() {
        assert_eq!(
            Bookmarks::sidecar_for(Path::new("/tmp/firmware.bin")),
            PathBuf::from("/tmp/firmware.bin.hexed-bookmarks")
        );
    }

    #[test]
    fn a_malformed_line_gives_a_readable_error() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bad");
        std::fs::write(&path, "# hexed bookmarks v1\nnot a number\tx\ty\tz\n").unwrap();
        let err = Bookmarks::load(&path).unwrap_err();
        assert!(err.detail.contains("line 2"));
    }
}
