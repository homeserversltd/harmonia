use super::ToolContract;

pub const NAME: &str = "systemd";
pub const DESCRIPTION: &str =
    "Systemd unit install/enable/disable/start/stop/restart/status primitive.";
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

pub fn systemd_request(action: impl Into<String>) -> Request {
    Request::new(action)
}

pub fn status(service: impl Into<String>) -> Request {
    Request {
        action: "status".to_string(),
        target: service.into(),
        args: Vec::new(),
    }
}
pub fn restart(service: impl Into<String>) -> Request {
    Request {
        action: "restart".to_string(),
        target: service.into(),
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
