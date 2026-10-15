//! Reading the cluster's report out of [`StartReport`] / [`TickReport`].

use crate::shared::ClusterReport;
use z_auth::controller::facade::{StartReport, TickReport};

/// `report.cluster()` — what the cluster did in this start or tick.
pub trait ClusterReportExt {
    fn cluster(&self) -> Option<&ClusterReport>;
}

impl ClusterReportExt for StartReport {
    fn cluster(&self) -> Option<&ClusterReport> {
        self.extension::<ClusterReport>()
    }
}

impl ClusterReportExt for TickReport {
    fn cluster(&self) -> Option<&ClusterReport> {
        self.extension::<ClusterReport>()
    }
}
