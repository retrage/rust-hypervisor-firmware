use core::fmt;

use atomic_refcell::AtomicRefCell;
use uart_16550::SerialPort;

// We use COM1 as it is the standard first serial port.
pub static PORT: AtomicRefCell<SerialPort> = AtomicRefCell::new(unsafe { SerialPort::new(0x3f8) });

pub struct Serial;
impl fmt::Write for Serial {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        PORT.borrow_mut().write_str(s)
    }
}

#[macro_export]
macro_rules! log {
    ($($arg:tt)*) => {{
        use core::fmt::Write;
        writeln!(crate::serial::Serial, $($arg)*).unwrap();
    }};
}
