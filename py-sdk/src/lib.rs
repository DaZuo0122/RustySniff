use pyo3::{prelude::*, wrap_pymodule};

pub mod types;

#[pymodule]
fn rustysniffpy(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_wrapped(wrap_pymodule!(types::statistic::statisticpy))?;
    m.add_wrapped(wrap_pymodule!(types::http::httpy))?;
    m.add_wrapped(wrap_pymodule!(types::tcp::tcpy))?;
    Ok(())
}
