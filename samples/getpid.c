static long raw_syscall0(long nr) {
  register long x8 __asm__("x8") = nr;
  register long x0 __asm__("x0") = 0;
  __asm__ volatile("svc #0" : "+r"(x0) : "r"(x8) : "memory");
  return x0;
}

int main(void) {
  return (int)raw_syscall0(172);
}
