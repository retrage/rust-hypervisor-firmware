.global hvc_call
.global psci_call_hvc
.section .text, "ax"

// https://github.com/tianocore/edk2/blob/master/ArmPkg/Library/ArmHvcLib/AArch64/ArmHvc.S
hvc_call:
  // Push x0 on the stack - The stack must always be quad-word aligned
  str x0, [sp, #-16]!

  // Load the HVC arguments values into the appropriate registers
  ldp x6, x7, [x0, #48]
  ldp x4, x5, [x0, #32]
  ldp x2, x3, [x0, #16]
  ldp x0, x1, [x0, #0]

  hvc #0

  // Pop the ARM_HVC_ARGS structure address from the stack into x9
  ldr x9, [sp], #16

  // Store the HVC returned values into the ARM_HVC_ARGS structure.
  // A HVC call can return up to 4 values
  stp x2, x3, [x9, #16]
  stp x0, x1, [x9, #0]

  mov x0, x9

  ret

psci_call_hvc:
  hvc #0
  ret