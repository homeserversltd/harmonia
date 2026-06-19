use super::ToolContract;

pub const NAME: &str = "package";
pub const DESCRIPTION: &str =
    "OS package check/update/install primitive; supports pacman first and later apt/dnf adapters.";
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

pub fn package_request(action: impl Into<String>) -> Request {
    Request::new(action)
}

pub fn check(packages: Vec<String>) -> Request {
    Request {
        action: "check".to_string(),
        target: "pacman".to_string(),
        args: packages,
    }
}
pub fn update() -> Request {
    Request {
        action: "update".to_string(),
        target: "pacman".to_string(),
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
