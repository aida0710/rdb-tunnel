#[derive(Debug)]
pub struct TaskState {
    pub reader_active: bool,
    pub writer_active: bool,
    pub analysis_active: bool,
}

impl TaskState {
    pub fn new() -> Self {
        Self {
            reader_active: false,
            writer_active: false,
            analysis_active: false,
        }
    }

    pub fn is_all_inactive(&self) -> bool {
        !self.reader_active && !self.writer_active && !self.analysis_active
    }
}
