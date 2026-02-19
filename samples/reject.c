#include <stdlib.h>

int main(void) {
  volatile long sys_nr = 172;
  register long x8 __asm__("x8") = sys_nr;
  register long x0 __asm__("x0");
  __asm__ volatile("svc #0\n" : "=r"(x0) : "r"(x8) : "memory", "cc");
  return (int)x0;
}
