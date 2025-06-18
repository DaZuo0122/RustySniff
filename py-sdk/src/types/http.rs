// src/http_wrapper.rs
use network::types::http::{self, HttpFilter, HttpMessage, f_process_http_1_x};
use pyo3::exceptions;
use pyo3::prelude::*;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

// Wrapper for HttpMessage
#[pyclass]
pub struct PyHttpMessage {
    #[pyo3(get)]
    pub src_ip: String,
    #[pyo3(get)]
    pub dst_ip: String,
    #[pyo3(get)]
    pub method: Option<String>,
    #[pyo3(get)]
    pub path: Option<String>,
    #[pyo3(get)]
    pub version: Option<u8>,
    #[pyo3(get)]
    pub status_code: Option<u16>,
    #[pyo3(get)]
    pub reason: Option<String>,
    #[pyo3(get)]
    pub headers: Vec<(String, String)>,
}

impl From<HttpMessage> for PyHttpMessage {
    fn from(msg: HttpMessage) -> Self {
        PyHttpMessage {
            src_ip: msg.src_ip.to_string(),
            dst_ip: msg.dst_ip.to_string(),
            method: msg.method,
            path: msg.path,
            version: msg.version,
            status_code: msg.status_code,
            reason: msg.reason,
            headers: msg.headers,
        }
    }
}

#[pymethods]
impl PyHttpMessage {
    fn __repr__(&self) -> String {
        if let Some(method) = &self.method {
            format!(
                "HttpRequest({} {} → {})",
                method,
                self.path.as_deref().unwrap_or(""),
                self.dst_ip
            )
        } else {
            format!(
                "HttpResponse({} ← {} {})",
                self.dst_ip,
                self.status_code.unwrap_or(0),
                self.reason.as_deref().unwrap_or("")
            )
        }
    }
}

// Wrapper for HttpFilter
#[pyclass]
#[derive(Clone)]
pub struct PyHttpFilter {
    inner: HttpFilter,
}

#[pymethods]
impl PyHttpFilter {
    #[new]
    fn new() -> Self {
        PyHttpFilter {
            inner: HttpFilter::default(),
        }
    }

    #[getter]
    fn src_ip(&self) -> Option<String> {
        self.inner.src_ip.as_ref().map(|ip| ip.to_string())
    }

    #[setter]
    fn set_src_ip(&mut self, ip: &str) -> PyResult<()> {
        self.inner.src_ip = Some(parse_ip(ip)?);
        Ok(())
    }

    #[getter]
    fn dst_ip(&self) -> Option<String> {
        self.inner.dst_ip.as_ref().map(|ip| ip.to_string())
    }

    #[setter]
    fn set_dst_ip(&mut self, ip: &str) -> PyResult<()> {
        self.inner.dst_ip = Some(parse_ip(ip)?);
        Ok(())
    }

    #[getter]
    fn method(&self) -> Option<String> {
        self.inner.method.clone()
    }

    #[setter]
    fn set_method(&mut self, method: &str) {
        self.inner.method = Some(method.to_string());
    }

    #[getter]
    fn status_code(&self) -> Option<u16> {
        self.inner.status_code
    }

    #[setter]
    fn set_status_code(&mut self, code: u16) {
        self.inner.status_code = Some(code);
    }

    #[getter]
    fn path_contains(&self) -> Option<String> {
        self.inner.path_contains.clone()
    }

    #[setter]
    fn set_path_contains(&mut self, substring: &str) {
        self.inner.path_contains = Some(substring.to_string());
    }
}

fn parse_ip(ip_str: &str) -> PyResult<IpAddr> {
    if let Ok(ipv4) = Ipv4Addr::from_str(ip_str) {
        Ok(IpAddr::V4(ipv4))
    } else if let Ok(ipv6) = Ipv6Addr::from_str(ip_str) {
        Ok(IpAddr::V6(ipv6))
    } else {
        Err(exceptions::PyValueError::new_err(format!(
            "Invalid IP address: {}",
            ip_str
        )))
    }
}

// Module initialization
#[pymodule]
pub fn httpy(_py: Python, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<PyHttpMessage>()?;
    m.add_class::<PyHttpFilter>()?;

    #[pyfn(m)]
    fn process_http_1_x(
        file_path: &str,
        filter: &PyHttpFilter,
        f_print: bool,
    ) -> PyResult<Option<Vec<PyHttpMessage>>> {
        let cap = pcap::Capture::from_file(file_path)
            .map_err(|e| exceptions::PyIOError::new_err(e.to_string()))?;

        let messages = http::f_process_http_1_x(cap, filter.inner.clone(), f_print);

        Ok(messages.map(|msgs| msgs.into_iter().map(PyHttpMessage::from).collect()))
    }

    Ok(())
}
