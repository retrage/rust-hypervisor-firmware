// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2024 Akira Moroo

use core::cell::SyncUnsafeCell;

use x86_64::structures::idt::{InterruptDescriptorTable, InterruptStackFrame};

static mut IDT: SyncUnsafeCell<InterruptDescriptorTable> =
    SyncUnsafeCell::new(InterruptDescriptorTable::new());

pub fn init() {
    let idt = unsafe { &mut *IDT.get() };
    idt.divide_error.set_handler_fn(divide_by_zero);
    idt.double_fault.set_handler_fn(double_fault_handler);
    idt.breakpoint.set_handler_fn(breakpoint_handler);
    idt.load();
}

extern "x86-interrupt" fn divide_by_zero(stack_frame: InterruptStackFrame) {
    panic!("EXCEPTION: DIVIDE BY ZERO\n{:#?}", stack_frame);
}

extern "x86-interrupt" fn double_fault_handler(
    stack_frame: InterruptStackFrame,
    error_code: u64,
) -> ! {
    panic!(
        "EXCEPTION: DOUBLE FAULT\n{:#?}\nERROR CODE: {}",
        stack_frame, error_code
    );
}

extern "x86-interrupt" fn breakpoint_handler(stack_frame: InterruptStackFrame) {
    log!("EXCEPTION: BREAKPOINT\n{:#?}", stack_frame);
}
