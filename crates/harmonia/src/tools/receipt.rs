use super::ToolContract;

pub const NAME: &str = "receipt";
pub const DESCRIPTION: &str = "Central receipt writer and run ledger primitive.";
pub const CONTRACT: ToolContract = ToolContract::new(NAME, DESCRIPTION);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    pub action: String,
    pub target: String,
    pub args: Vec<String>,
}

impl Request {
    pub fn new(action: impl Into<String>) -> Self {
        Self {
            action: action.into(),
            target: NAME.to_string(),
            args: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Outcome {
    pub ok: bool,
    pub changed: bool,
    pub message: String,
}

pub fn receipt_request(action: impl Into<String>) -> Request {
    Request::new(action)
}

pub fn write_run(receipt_dir: impl Into<String>) -> Request {
    Request {
        action: "write-run".to_string(),
        target: receipt_dir.into(),
        args: Vec::new(),
    }
}

pub fn plan(request: &Request) -> Outcome {
    Outcome {
        ok: true,
        changed: false,
        message: format!("{} {} planned for {}", NAME, request.action, request.target),
    }
}
