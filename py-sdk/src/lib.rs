use pyo3::prelude::*;

pub mod types;

#[pymodule]
fn rustysniffpy(py: Python, m: &Bound<'_, PyModule>) -> PyResult<()> {
    crate::types::statistic::statisticpy(py, m)?;
    crate::types::http::httpy(py, m)?;
    crate::types::tcp::tcpy(py, m)?;
    Ok(())
}
