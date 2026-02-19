  .section .text.startup, "ax", @progbits
  .global _start
  .type _start, %function
_start:
  bl main
  b exit
1:
  b 1b
  .size _start, .-_start

  .global exit
  .type exit, %function
exit:
  mov x8, #93
  svc #0
2:
  b 2b
  .size exit, .-exit
